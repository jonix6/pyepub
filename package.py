
import utils
from collections import namedtuple, defaultdict
from lxml import etree, html
from lxml.builder import ElementMaker
import cssutils
import os
import io
from urllib.parse import urlparse

import zipfile
from container import epubContainer

DC_TAGS = [
	'contributor', 'coverage', 'creator',
	'date', 'description', 'format',
	'identifier', 'language', 'publisher',
	'relation', 'rights', 'source',
	'subject', 'title', 'type'
]

class epubNav:
	namespaces = {
		'ncx': 'http://www.daisy.org/z3986/2005/ncx/',
		'epub': 'http://www.idpf.org/2007/ops',
		'html': 'http://www.w3.org/1999/xhtml'
	}
	def __init__(self):
		self.toc_title = ''
		self.pagelist_title = ''
		self.toc = []
		self.pagelist = []
		self.landmarks = []

	def parse_epub2(self, ncx, ncxpath):
		def iter_node(node, tag, depth=1, walk=True):
			for point in node.xpath(tag, namespaces=self.namespaces):
				label = point.xpath('ncx:navLabel/ncx:text/text()', namespaces=self.namespaces)[0]
				target = point.xpath('ncx:content/@src', namespaces=self.namespaces)[0]
				yield label, target, depth
				if walk:
					yield from iter_node(point, tag, depth=depth+1, walk=True)

		navmap = ncx.find('{%s}navMap' % self.namespaces['ncx'])
		for label, target, depth in iter_node(navmap, 'ncx:navPoint'):
			target = utils.realpath(target, ncxpath)
			self.toc.append((label, target, depth))

		pagelist = ncx.find('{%s}pageList' % self.namespaces['ncx'])
		if pagelist is not None:
			for label, target, depth in iter_node(pagelist, 'ncx:navTarget', walk=False):
				target = utils.realpath(target, ncxpath)
				self.pagelist.append(label, target)

	def parse(self, doc, docpath):
		def iter_node(node, depth=1, walk=True):
			sublist = node.find('html:ol', namespaces=self.namespaces)
			if sublist is None:
				return
			for subnode in sublist.findall('html:li', namespaces=self.namespaces):
				target_node = subnode.xpath('html:a|html:span', namespaces=self.namespaces)
				if not target_node: continue
				target = target_node[0].get('href', '')
				epub_type = target_node[0].get('{%s}type' % self.namespaces['epub'], '')
				content = etree.tostring(target_node[0], encoding='utf-8', method='html').decode('utf-8')
				yield content, target, depth, epub_type
				if walk:
					yield from iter_node(subnode, depth=depth+1, walk=True)
		def get_title(node):
			title_node = node.xpath('html:*[starts-with(name(),"h")]', namespaces=self.namespaces)
			if not title_node: return ''
			return etree.tostring(title_node[0], encoding='utf-8', method='html').decode('utf-8').strip()

		nav = doc.find('html:body//html:nav[@epub:type="toc"]', namespaces=self.namespaces)
		self.toc_title = get_title(nav)
		for label, target, depth, _ in iter_node(nav):
			if target:
				target = utils.realpath(target, docpath)
			self.toc.append((label, target, depth))

		pagelist = doc.find('html:body//html:nav[@epub:type="page-list"]', namespaces=self.namespaces)
		if pagelist is not None:
			self.pagelist_title = get_title(pagelist)
			for label, target, _, __ in iter_node(pagelist, walk=False):
				target = utils.realpath(target, docpath)
				self.pagelist.append((label, target))

		landmarks = doc.find('html:body//html:nav[@epub:type="landmarks"]', namespaces=self.namespaces)
		if landmarks is not None:
			for label, target, _, epub_type in iter_node(landmarks, walk=False):
				target = utils.realpath(target, docpath)
				self.landmarks.append((epub_type, target, label))

	def insert_toc(self, index, content, target='', parent=''):
		parent = list(map(int, filter(None, parent.split('.'))))
		if not parent:
			self.toc.insert(index, (content, target, 1))
			return str(index+1)
		
		curindex = [0]
		tail = None
		siblings = []
		for i, (_, __, depth) in enumerate(self.toc):
			if depth > len(curindex):
				curindex.append(0)
			elif depth < len(curindex):
				del curindex[depth-len(curindex):]
			curindex[-1] += 1
			
			if curindex == parent:
				tail = i+1, tuple(curindex+[1])

			if curindex[:len(parent)] == parent:
				if len(curindex) == len(parent) + 1:
					siblings.append( (i, tuple(curindex)) )
			elif all(curindex[j] >= parent[j] for j in range(depth)):
				if len(curindex) < len(parent):
					continue
				j, curindex = siblings[-1]
				*j, last = curindex
				tail = i, tuple(j+[last+1])
				break

			if not siblings: continue
			if len(siblings) == index+1:
				i, curindex = siblings[-1]
				self.toc.insert(i, (content, target, len(curindex)))
				return '.'.join(map(str, curindex))

		if tail:
			i, curindex = tail
			self.toc.insert(i, (content, target, len(parent)+1))
			return '.'.join(map(str, curindex))

	def append_toc(self, content, target='', parent=''):
		return self.insert_toc(-1, content, target, parent)

	def add_landmark(self, reftype, target, label):
		self.landmarks.append(reftype, target, label)


class epubPackage:
	namespaces = {
		'opf': 'http://www.idpf.org/2007/opf',
		'dc': 'http://purl.org/dc/elements/1.1/'
	}
	export_options = dict(
		opf_path = 'OEBPS/content.opf',
		toc_path = 'OEBPS/toc',
		resource_dir = {
			'document': 'OEBPS/Text',
			'image': 'OEBPS/Images',
			'stylesheet': 'OEBPS/Styles',
			'font': 'OEBPS/Font',
			'script': 'OEBPS/Scripts',
			'other': 'OEBPS/Misc'
		}
	)
	def __init__(self):
		# default package settings
		self.version = utils.version3.v3_2
		uid = namedtuple('uid', ['key', 'value', 'props'])
		self.uid = uid(key='BookId', value='', props={})

		# basic package records
		self.resources = {}
		self.metadata = defaultdict(list)
		self.manifest = defaultdict(set)
		self.spine = []
		self.nav = epubNav()

		# resource extended attributes
		self.properties = {
			'cover-image': '',
			'mathml': [],
			'nav': '',
			'remote-resources': [],
			'scripted': [],
			'svg': []
		}
		self.fallbacks = {}

		self.doc_loaders = {
			'head/link[@rel="stylesheet"]': ('href', self.add_stylesheet),
			'body//map/area': ('href', self.add_image),
			'body//img': ('src', self.add_image),
			'body//audio|body//video': ('src', self.add_resource),
			'body//audio/source|body//video/source': ('src', self.add_resource),
			'//script': ('src', self.add_resource)
		}

	def is_epub3(self):
		return self.version in utils.version3

	def set_uid(self, value, key='', props={}):
		self.uid = self.uid._replace(key=key or self.uid.key, value=value, props=props)

	def set_property(self, iid, *props):
		for prop in props:
			if not prop in self.properties: continue
			target = self.properties[prop]
			if isinstance(target, list):
				target.append(iid)
			else:
				self.properties[prop] = iid

	def set_fallback(self, iid, fallback):
		self.fallbacks[iid] = fallback

	def set_metadata(self, entry, value, where={}, append=False):
		if entry == 'cover' and not self.is_epub3():
			self.set_property(value, 'cover-image')
			return
		values = self.metadata[entry]
		if append or not values:
			values.append((value, where))
			return
		i = 0
		for v, attr in values:
			if not where:
				break
			if all(attr.get(kw) == vw for kw,vw in where.items()):
				break
			i += 1
		if i < len(values):
			v, attr = values[i]
			values[i] = (value, attr)
		else:
			values.append((value, where))

	def open_path(self, path, source=None):
		try:
			if source:
				fp = source.open(path)
			else:
				fp = io.open(path, 'rb')
			return fp
		except IOError:
			return

	def open(self, iid):
		path, source, mimetype = self.resources[iid]
		fp = self.open_path(path, source)
		if not fp and iid in self.fallbacks:
			return self.open(self.fallbacks[iid])
		return fp

	def add_document(self, path, basepath='', source=None, index=-1, linear=True, props=[]):
		path = utils.realpath(path, basepath)
		fp = self.open_path(path, source)
		if not fp: return
		doc = html.parse(fp)
		for findpath, (attr, loader) in self.doc_loaders.items():
			for el in doc.xpath(findpath):
				url = el.get(attr, '')
				mimetype = el.get('type', '')
				if not url: continue
				urlp = urlparse(url)
				if urlp.netloc: continue
				loader(urlp.path, basepath=path, source=source, mimetype=mimetype)
		fp.close()
		docid = os.path.basename(path)
		mimetype = utils.mimetypes['.xhtml']
		self.resources[docid] = path, source, mimetype
		self.manifest['document'].add(docid)
		self.add_spine(docid, index=index, linear=linear, props=props)
		return docid

	def add_stylesheet(self, path, basepath='', source=None, mimetype=''):
		path = utils.realpath(path, basepath)
		fp = self.open_path(path, source)
		if fp:
			sheet = cssutils.parseString(fp.read(), validate=False)
			for url in cssutils.getUrls(sheet):
				urlp = urlparse(url)
				if urlp.netloc: continue
				self.add_resource(urlp.path, basepath=path, source=source)
			fp.close()
		iid = os.path.basename(path)
		mimetype = utils.mimetypes['.css']
		self.resources[iid] = path, source, mimetype
		self.manifest['stylesheet'].add(iid)
		return iid

	def add_image(self, path, basepath='', source=None, mimetype=''):
		fname, ext = utils.filename(path)
		mimetype = mimetype or utils.mimetypes.get(ext, 'text/plain')
		if not mimetype.startswith('image/'): return

		path = utils.realpath(path, basepath)
		iid = fname+ext
		self.resources[iid] = path, source, mimetype
		self.manifest['image'].add(iid)
		return iid

	def add_resource(self, path, basepath='', source=None, mimetype='', load=True):
		fname, ext = utils.filename(path)
		mimetype = mimetype or utils.mimetypes.get(ext)
		res_type = utils.restypes.get(mimetype, 'other')
		if load:
			loader = getattr(self, 'add_'+res_type, None)
			if loader:
				return loader(path, basepath=basepath, source=source, mimetype=mimetype)

		path = utils.realpath(path, basepath)
		iid = fname+ext
		self.resources[iid] = path, source, mimetype
		self.manifest[res_type].add(iid)
		return iid

	def add_spine(self, docid, index=-1, linear=True, props=[]):
		assert docid in self.manifest['document']
		self.spine.insert(index, (docid, linear, props))

	def add_toc(self, label, docid='', anchor='', index=-1, parent=''):
		target = ''
		if docid:
			path, source, mime = self.resources[docid]
			target = path + '#' + anchor
		return self.nav.insert_toc(index, label, target=target, parent=parent)

	def load_package(self, epub, rootfile):
		with epub.open(rootfile) as fp:
			opf = etree.parse(fp)
		root = opf.getroot()
		self.version = root.attrib['version']
		assert self.version in utils.version2 or self.version in utils.version3
		self.uid = self.uid._replace(key=root.attrib['unique-identifier'])

		metadata = opf.find('{%s}metadata' % self.namespaces['opf'])
		self._load_metadata(metadata)

		manifest = opf.find('{%s}manifest' % self.namespaces['opf'])
		for iid, href, mime, fallback, props in self._load_manifest(manifest):
			self.set_property(iid, *props)
			self.set_fallback(iid, fallback)
			self._load_resource(iid, href, mime, basepath=rootfile, source=epub)

		spine = opf.find('{%s}spine' % self.namespaces['opf'])
		self._load_spine(spine)

		if self.properties['nav']:
			self._load_toc(self.properties['nav'])

		if not self.is_epub3():
			guide = opf.find('{%s}guide' % self.namespaces['opf'])
			if guide is not None:
				self._load_guide(guide, rootfile)

	def _load_resource(self, iid, path, mimetype, basepath='', source=None):
		res_type = utils.restypes.get(mimetype, 'other')
		path = utils.realpath(path, basepath)
		self.resources[iid] = path, source, mimetype
		self.manifest[res_type].add(iid)

	def _load_metadata(self, metadata):
		idmap = {}
		for el in metadata.iterchildren():
			tag = etree.QName(el)
			ns, entry = tag.namespace, tag.localname
			value = el.text
			_attr = dict(el.attrib)
			attr = {}
			for key, prop in _attr.items():
				key = etree.QName(key)
				if key.namespace and key.namespace != self.namespaces['opf']:
					continue
				attr[key.localname] = prop

			if not ns in self.namespaces.values(): continue
			if ns == self.namespaces['dc']:
				if not entry in DC_TAGS: continue
			elif self.is_epub3():
				entry = attr.pop('property')
			else:
				entry = attr.pop('name')
				value = attr.pop('content')
			
			if tag.localname == 'meta' and el.get('refines'):
				iid = el.get('refines')[1:]
				if not idmap.get(iid): continue
				_entry, _value, _attr = idmap[iid]
				idmap[iid] = _entry, _value, dict(_attr, **{entry: value})
				continue
			if el.get('id') is not None:
				idmap[attr.pop('id')] = (entry, value, attr)
				continue
			self.set_metadata(entry, value, where=attr)

		for iid, (entry, value, attr) in idmap.items():
			if iid == self.uid.key and entry == 'identifier':
				self.uid = self.uid._replace(value=value, props=attr)
				continue
			self.set_metadata(entry, value, where=attr)

	def _load_manifest(self, manifest):
		for item in manifest.xpath('opf:item', namespaces=self.namespaces):
			iid = item.get('id')
			href = item.get('href')
			media_type = item.get('media-type')
			fallback = item.get('fallback')
			props = []
			if 'properties' in item.attrib:
				props = item.get('properties').split(' ')

			yield iid, href, media_type, fallback, props

	def _load_spine(self, spine):
		for itemref in spine.iterchildren():
			idref = itemref.attrib['idref']
			linear = itemref.attrib.get('linear', True)
			linear = False if linear == 'no' else True
			props = []
			if 'properties' in itemref:
				props = itemref.get('properties').split(' ')
			self.spine.append((idref, linear, props))

	def _load_toc(self, iid):
		path, source, mime = self.resources[iid]
		if self.is_epub3():
			if mime != utils.mimetypes['.xhtml']:
				return
			with self.open(iid) as fp:
				doc = etree.parse(fp)
				self.nav.parse(doc, path)
		else:
			assert mime == utils.mimetypes['.ncx']
			with self.open(iid) as fp:
				tree = etree.parse(fp)
				self.nav.parse_epub2(tree, path)

	def _load_guide(self, guide, rootfile):
		assert not self.is_epub3()
		for ref in guide.findall('opf:reference', namespaces=self.namespaces):
			target = ref.attrib['href']
			reftype = ref.attrib['type']
			label = ref.attrib['title']
			target = utils.realpath(target, rootfile)
			self.nav.landmarks.append(reftype, target, label)

	def set_toc(self, iid, mimetype):
		if self.is_epub3():
			if mimetype != utils.mimetypes['.xhtml']:
				return
		else:
			assert mimetype == utils.mimetypes['.ncx']
		self.properties['nav'] = iid

	def get_properties(self, iid):
		props = []
		for prop, value in self.properties.items():
			if isinstance(value, list):
				if iid in value:
					props.append(prop)
			elif value == iid:
				props.append(prop)
		return props

	def get_metadata(self, entry, where={}):
		values = self.metadata[entry]
		if not where:
			return [x[0] for x in values]
		for value, attr in values:
			if all(attr.get(kw) == vw for kw,vw in where.items()):
				return value

	def export_opf(self, options=export_options):
		xmlns = self.namespaces['opf']
		xmlnsDC = self.namespaces['dc']
		E = ElementMaker(namespace=xmlns, nsmap={None: xmlns})
		dcE = ElementMaker(namespace=xmlnsDC, nsmap={None: xmlnsDC, 'opf': xmlns})
		metaE = ElementMaker(nsmap={'opf': xmlns, 'dc': xmlnsDC})

		if self.properties['cover-image']:
			iid = self.properties['cover-image']
			if not self.is_epub3():
				self.set_metadata('cover', iid)

		metadata = metaE.metadata()
		not_refinable = not self.is_epub3() or self.version == utils.version3.v3_1
		el = dcE.identifier(self.uid.value, {'id': self.uid.key})
		metadata.append(el)
		for k, v in self.uid.props.items():
			if not_refinable:
				el.attrib['{%s}' % self.namespaces['opf']+k] = v
			else:
				metadata.append(metaE.meta(v, dict(refines='#'+self.uid.key, property=k)))
		
		for entry, values in self.metadata.items():
			for i, (value, _attr) in enumerate(
				sorted(values, key=lambda x: x[1].pop('display-seq', 0))):
				iid = entry + '-' + str(i+1)

				if entry in DC_TAGS:
					el = dcE(entry, value)
				elif self.is_epub3():
					el = metaE('meta', value, dict(property=entry))
				else:
					el = metaE('meta', dict(name=entry, content=value))
				metadata.append(el)

				for k, v in _attr.items():
					if not_refinable:
						el.attrib['{%s}' % self.namespaces['opf']+k] = v
						continue
					el.attrib['id'] = iid
					metadata.append(metaE.meta(v, dict(refines='#'+iid, property=k)))

		manifest = E.manifest()
		for res_type, itemset in self.manifest.items():
			for iid in itemset:
				path, source, mime = self.resources[iid]
				new_path = os.path.join(options['resource_dir'][res_type], os.path.basename(path))
				if iid == self.properties['nav']:
					ext = '.xhtml' if self.is_epub3() else '.ncx'
					new_path = options['toc_path'] + ext
					mime = utils.mimetypes[ext]
				path = utils.refpath(new_path, options['opf_path'])
				el = E.item(dict({'id': iid, 'href': path, 'media-type': mime}))
				if self.fallbacks.get(iid):
					el.attrib['fallback'] = self.fallbacks[iid]
				if self.is_epub3():
					props = self.get_properties(iid)
					if props:
						el.attrib['properties'] = ' '.join(props)
				manifest.append(el)

		spine = E.spine()
		if not self.is_epub3():
			spine.attrib['toc'] = self.properties['nav']
		for cid, linear, props in self.spine:
			if not self.is_epub3() and cid == self.properties['nav']:
				continue
			assert cid in self.manifest['document']
			attr = {'idref': cid}
			if not linear: attr['linear'] = 'no'
			if props and self.is_epub3():
				attr['properties'] = ' '.join(props)
			spine.append(E.itemref(attr))

		package = E.package({'version': self.version, 'unique-identifier': self.uid.key}, metadata, manifest, spine)

		if not self.is_epub3() and self.nav.landmarks:
			guide = E.guide()
			for reftype, path, label in self.nav.landmarks:
				new_path = os.path.join(options['resource_dir']['document'], os.path.basename(path))
				path = utils.refpath(new_path, options['opf_path'])
				label = etree.tostring(html.fromstring(label), method='text', encoding='utf-8').decode('utf-8').strip()
				guide.append(E.reference(dict(type=reftype, href=path, title=label)))
			package.append(guide)

		output = io.BytesIO()
		etree.ElementTree(package).write(output, encoding='utf-8', xml_declaration=True, pretty_print=True)
		output.seek(0)
		return output

	def export_nav_epub2(self, options=export_options):
		xmlns = self.nav.namespaces['ncx']
		ncxE = ElementMaker(namespace=xmlns, nsmap={None: xmlns})

		navMap = ncxE.navMap()
		parents = [navMap]
		for i, (content, path, depth) in enumerate(self.nav.toc):
			content = etree.tostring(
				html.fromstring(content), encoding='utf-8', method='text'
			).decode('utf-8').strip()
			if path:
				new_path = os.path.join(options['resource_dir']['document'], os.path.basename(path))
				path = utils.refpath(new_path, options['toc_path']+'.ncx')
			point = ncxE.navPoint({'id': 'navPoint-%d' % (i+1)}, 
				ncxE.navLabel( ncxE.text(content) ),
				ncxE.content({'src': path})
			)
			if len(parents) < depth + 1:
				if depth > len(parents) + 1:
					continue
				parents.append(point)
			parents[depth-1].append(point)
			parents[depth] = point

		ncx = ncxE.ncx({'version': '2005-1'}, 
			ncxE.head(
				ncxE.meta({'name': 'dtb:uid', 'content': self.uid.value})
			), 
			ncxE.docTitle(
				ncxE.text(self.get_metadata('title')[0])
			), 
			navMap)

		if self.nav.pagelist:
			pagelist = ncxE.pageList()
			for i, (content, path) in enumerate(self.nav.pagelist):
				content = etree.tostring(
					etree.fromstring(content), encoding='utf-8', method='text'
				).decode('utf-8').strip()
				if path:
					new_path = os.path.join(options['resource_dir']['document'], os.path.basename(path))
					path = utils.refpath(new_path, options['toc_path']+'.ncx')
				point = ncxE.pageTarget({'id': 'pageTarget-%d' % (i+1), 'type': 'normal'}, 
					ncxE.navLabel( ncxE.text(content) ),
					ncxE.content({'src': path})
				)
				pagelist.append(point)
			ncx.append(pagelist)

		output = io.BytesIO()
		etree.ElementTree(ncx).write(output, encoding='utf-8', xml_declaration=True, pretty_print=True)
		output.seek(0)
		return output

	def export_nav(self, options=export_options):
		if not self.is_epub3():
			return self.export_nav_epub2(options=options)

		xmlns = self.nav.namespaces['html']
		xmlnsEpub = self.nav.namespaces['epub']
		E = ElementMaker(namespace=xmlns, nsmap={None: xmlns, 'epub': xmlnsEpub})

		toc = E.nav({'{%s}type' % xmlnsEpub: 'toc'})
		if self.nav.toc_title:
			el = etree.fromstring(self.nav.toc_title)
			el.tag = 'h2' if not el.tag.startswith('h') else el.tag
			toc.append(etree.fromstring(self.nav.toc_title))
		parents = [toc]
		for content, path, depth in self.nav.toc:
			el = html.fromstring(content)
			if path:
				new_path = os.path.join(options['resource_dir']['document'], os.path.basename(path))
				path = utils.refpath(new_path, options['toc_path']+'.xhtml')
				el.tag = 'a'
				el.set('href', path)
			else:
				el.tag = 'span'
			li = E.li()
			li.append(el)

			if len(parents) < depth + 1:
				if depth > len(parents) + 1:
					continue
				parents.append(li)
			parent = parents[depth-1].find('{%s}ol' % xmlns)
			if parent is None:
				ol = E.ol()
				parents[depth-1].append(ol)
				parent = ol
			parent.append(li)
			parents[depth] = li

		body = E.body(toc)

		if self.nav.pagelist:
			pagelist = E.nav({'{%s}type' % xmlnsEpub: 'page-list'})
			if self.nav.pagelist_title:
				el = etree.fromstring(self.nav.pagelist_title)
				el.tag = 'h2' if not el.tag.startswith('h') else el.tag
				pagelist.append(el)
			parent = E.ol()
			pagelist.append(parent)
			for content, path in self.nav.pagelist:
				el = etree.fromstring(content)
				new_path = os.path.join(options['resource_dir']['document'], os.path.basename(path))
				path = utils.refpath(new_path, options['toc_path']+'.xhtml')
				el.tag = 'a'
				el.set('href', path)
				parent.append(E.li(el))
			body.append(pagelist)

		doc = E.html(
			E.head(E.title(self.get_metadata('title')[0])), body
		)

		output = io.BytesIO()
		etree.ElementTree(doc).write(output, encoding='utf-8', xml_declaration=True, pretty_print=True, doctype='<!DOCTYPE html>')
		output.seek(0)
		return output

	def export_epub(self, dest, options=export_options):
		output = zipfile.ZipFile(dest, 'w')
		output.writestr('mimetype', utils.MIMETYPE, zipfile.ZIP_STORED)
		container = epubContainer()
		container.rootfiles = [options['opf_path']]
		for path, data in container.export():
			output.writestr(path, data, zipfile.ZIP_DEFLATED)

		if not self.get_metadata('title'):
			self.set_metadata('title', 'untitled')
		if not self.get_metadata('language'):
			self.set_metadata('language', 'en-US')
		if not self.nav.toc:
			idref, _, __ = self.spine[0]
			self.add_toc('Start of Content', docid=idref)

		with self.export_nav(options=options) as fp:
			ext = '.xhtml' if self.is_epub3() else '.ncx'
			toc_path = options['toc_path'] + ext
			output.writestr(toc_path, fp.read(), zipfile.ZIP_DEFLATED)
			if not self.properties['nav']:
				iid = self.add_resource(toc_path, source=output, load=False)
				self.set_property(iid, 'nav')

		with self.export_opf(options=options) as fp:
			output.writestr(options['opf_path'], fp.read(), zipfile.ZIP_DEFLATED)

		for res_type, values in self.manifest.items():
			for iid in values:
				fp = self.open(iid)
				if not fp: continue
				path, source, mime = self.resources[iid]
				new_path = os.path.join(options['resource_dir'][res_type], os.path.basename(path))
				output.writestr(new_path, fp.read(), zipfile.ZIP_DEFLATED)
				fp.close()

		output.close()

if __name__ == '__main__':
	from uuid import uuid4
	package = epubPackage()
	package.load_epub('s04.xhtml')
	package.version = '2.0'
	package.export_epub('new.epub')
	# with package.export_opf() as fp:
	# 	print(fp.read().decode('utf-8'))
