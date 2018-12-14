
import re
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
from contentdocs import contentDocs

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
				target_node = target_node[0]
				etree.cleanup_namespaces(target_node)
				target = target_node.get('href', '')
				epub_type = target_node.get('{%s}type' % self.namespaces['epub'], '')
				content = etree.tostring(target_node, encoding='utf-8', method='html').decode('utf-8')
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

	def enum_toc(self):
		curindex = [0]
		for i, (label, href, depth) in enumerate(self.toc):
			if depth > len(curindex):
				curindex.append(0)
			elif depth < len(curindex):
				del curindex[depth-len(curindex):]
			curindex[-1] += 1
			yield curindex, (label, href, depth)

	def get(self, index):
		if isinstance(index, (int, float)): index = str(index)
		index = list(map(int, index.split('.')))
		for curindex, (label, href, depth) in self.enum_toc():
			if curindex == index:
				return label, href, depth

	def search(self, pattern):
		pattern = r'\s+'.join(re.compile(r'\s+').split(pattern))
		reobj = re.compile(pattern, re.I)
		for curindex, (label, _, __) in self.enum_toc():
			label = etree.tostring(etree.fromstring(label), 
				method='text', encoding='utf-8').decode('utf-8').strip()
			if reobj.search(label):
				return '.'.join(map(str, curindex))

	def insert_toc(self, index, content, target='', parent=''):
		parent = list(map(int, filter(None, parent.split('.'))))
		if not parent:
			self.toc.insert(index, (content, target, 1))
			return str(index+1)

		tail = None
		siblings = []
		for i, (curindex, (_, __, depth)) in enumerate(self.enum_toc()):
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
	def __init__(self):
		# default package settings
		self.version = utils.version3.v3_2
		uid = namedtuple('uid', ['key', 'value', 'props'])
		self.uid = uid(key='BookId', value='', props={})
		self.page_direction = 'default'
		self.language = 'en'

		# basic package records
		self.metadata = defaultdict(list)
		self.idmap = {}
		self.router = {}
		self.spine = []
		self.contents = contentDocs()
		self.nav = epubNav()
		self.cover = ''

		# resource extended attributes
		self.properties = defaultdict(set)
		self.fallbacks = {}

	def is_epub3(self):
		return self.version in utils.version3

	"get/set package metadata"
	def set_metadata(self, entry, value, where={}, add=True):
		if entry == 'language':
			self.language = value
			return
		if entry == 'cover' and not self.is_epub3():
			self.cover = value
			return
		values = self.metadata[entry]
		if add or not values:
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

	def set_metadata_properties(self, entry, value, props):
		for v, attr in self.metadata[entry]:
			if value == v:
				attr.update(props)
				return

	def get_metadata(self, entry, where={}):
		values = self.metadata[entry]
		if not where:
			return [x[0] for x in values]
		for value, attr in values:
			if all(attr.get(kw) == vw for kw,vw in where.items()):
				return value

	def set_identifier(self, value, scheme='', unique=True):
		if unique:
			self.uid.props['scheme'] = scheme or self.uid.props['scheme']
			self.uid = self.uid._replace(value=value)
			return
		where = {}
		if scheme: where['scheme'] = scheme
		self.set_metadata('identifier', value, where, add=False)

	def set_title(self, title, title_type='main'):
		self.set_metadata('title', title, {'title-type': title_type}, add=False)

	def add_author(self, author, role='author', role_lang='en'):
		lang_order = ['en', 'cn']
		for code, roles in utils.marc_codes.items():
			_role = roles[lang_order.index(role_lang)]
			if role == _role:
				self.set_metadata('creator', author, {'role': code})
				return
		self.set_metadata('creator', author, {'role': 'oth'})

	def _load_metadata(self, metadata, add=True):
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
				if not value: continue
			elif entry == 'meta':
				if self.is_epub3():
					entry = attr.pop('property', None)
				else:
					entry = attr.pop('name')
					value = attr.pop('content')
			else: continue
			
			if entry == 'meta' and el.get('refines'):
				iid = el.get('refines')[1:]
				if not idmap.get(iid): continue
				self.set_metadata_properties(_entry, _value, {entry: value})
				continue
			if el.get('id'):
				idmap[attr.pop('id')] = (entry, value, attr)
				continue
			self.set_metadata(entry, value, where=attr, add=add)

		for iid, (entry, value, attr) in idmap.items():
			if iid == self.uid.key and entry == 'identifier':
				self.uid.props.update(attr)
				self.uid = self.uid._replace(value=value)
				continue
			self.set_metadata(entry, value, where=attr, add=add)

	"resource management - id-mapping, url-routing"
	def register(self, iid, path, openfunc=None, mimetype='text/plain'):
		self.idmap[iid] = path
		self.router[path] = openfunc, mimetype

	def route(self, path):
		res = self.router.get(path)
		if res is None:
			return None, ''
		openfunc, mimetype = res
		return openfunc, mimetype

	def open(self, iid):
		path = self.idmap[iid]
		openfunc, mimetype = self.route(path)
		try:
			if openfunc:
				fp = openfunc(path)
			else:
				fp = io.open(path, 'rb')
			return path, fp, mimetype
		except:
			if iid in self.fallbacks:
				return self.open(self.fallbacks[iid])
			return path, None, mimetype

	"get/set item properties"
	def set_property(self, iid, *props):
		for prop in props:
			if prop == 'cover-image':
				self.cover = iid
				continue
			if prop == 'nav':
				self._load_nav(iid)
				continue
			self.properties[prop].add(iid)

	def get_properties(self, iid):
		props = []
		for prop, values in self.properties.items():
			if iid in value:
				props.append(prop)
		return props

	def _load_manifest(self, manifest):
		for item in manifest.findall('opf:item', namespaces=self.namespaces):
			iid = item.get('id')
			href = item.get('href')
			mimetype = item.get('media-type')
			fallback = item.get('fallback')
			props = []
			if 'properties' in item.attrib:
				props = item.get('properties').split(' ')

			yield iid, href, mimetype, fallback, props

	"add various resource"
	def add_resource(self, path, openfunc=None, iid='', mimetype=''):
		fname, ext = utils.filename(path)
		mimetype = mimetype or utils.mimetypes.get(ext, 'text/plain')
		iid = iid or fname+ext
		self.register(iid, path, openfunc, mimetype)
		return iid

	"navigation managing"
	def _load_nav(self, iid):
		path, fp, mimetype = self.open(iid)
		if self.is_epub3():
			if mimetype == utils.mimetypes['.xhtml']:
				doc = etree.parse(fp)
				self.nav.parse(doc, path)
				fp.close()
				return
		assert mimetype == utils.mimetypes['.ncx']
		ncx = etree.parse(fp)
		self.nav.parse_epub2(ncx, path)
		fp.close()

	"content document managing"
	def _load_spine(self, spine):
		if self.is_epub3():
			self.page_direction = spine.get('page-progression-direction', 'default')
		else:
			self._load_nav(spine.get('toc'))
		for itemref in spine.iterchildren():
			idref = itemref.get('idref')
			path = self.idmap[idref]
			openfunc, mimetype = self.route(path)
			assert mimetype == utils.mimetypes['.xhtml']
			linear = itemref.get('linear', 'yes')
			linear = False if linear == 'no' else True
			props = []
			if 'properties' in itemref:
				props = itemref.get('properties').split(' ')
			self.spine.append((path, openfunc, linear, props))

	def add_document(self, path, openfunc=None, index=-1, linear=True, props=[]):
		self.spine.insert(index, (path, openfunc, linear, props))

	def add_stylesheet(self, path, basepath='', openfunc=None, mimetype=''):
		path = utils.realpath(path, basepath)
		iid = os.path.basename(path)
		mimetype = utils.mimetypes['.css']
		self.register(iid, path, openfunc, mimetype)

		fp, _ = self.route(path)
		if fp:
			sheet = cssutils.parseString(fp.read(), validate=False)
			for url in cssutils.getUrls(sheet):
				urlp = urlparse(url)
				if urlp.netloc: continue
				self.add_resource(urlp.path, basepath=path, openfunc=openfunc)
			fp.close()
		return iid

	def _load_guide(self, guide, rootfile):
		assert not self.is_epub3()
		for ref in guide.findall('opf:reference', namespaces=self.namespaces):
			target = ref.attrib['href']
			reftype = ref.attrib['type']
			label = ref.attrib['title']
			target = utils.realpath(target, rootfile)
			self.nav.landmarks.append(reftype, target, label)

	def load_package(self, reader, rootfile):
		with reader.open(rootfile) as fp:
			parser = etree.XMLParser(remove_comments=True)
			opf = etree.parse(fp, parser)
		root = opf.getroot()
		self.version = root.attrib['version']
		assert self.version in utils.version2 or self.version in utils.version3
		self.uid = self.uid._replace(key=root.attrib['unique-identifier'])

		metadata = opf.find('{%s}metadata' % self.namespaces['opf'])
		self._load_metadata(metadata)

		manifest = opf.find('{%s}manifest' % self.namespaces['opf'])
		for iid, href, mimetype, fallback, props in self._load_manifest(manifest):
			self.set_property(iid, *props)
			if fallback:
				self.fallbacks[iid] = fallback
			href = utils.realpath(href, rootfile)
			self.add_resource(href, readfunc=reader.open, iid=iid, mimetype=mimetype)

		spine = opf.find('{%s}spine' % self.namespaces['opf'])
		self._load_spine(spine)

		if not self.is_epub3():
			guide = opf.find('{%s}guide' % self.namespaces['opf'])
			if guide is not None:
				self._load_guide(guide, rootfile)

	def set_toc(self, iid, mimetype):
		if self.is_epub3():
			if mimetype != utils.mimetypes['.xhtml']:
				return
		else:
			assert mimetype == utils.mimetypes['.ncx']
		self.properties['nav'] = iid

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
				path, fp, mimetype = self.open(iid)
				new_path = os.path.join(options['resource_dir'][res_type], os.path.basename(path))
				if iid == self.properties['nav']:
					ext = '.xhtml' if self.is_epub3() else '.ncx'
					new_path = options['toc_path'] + ext
					mimetype = utils.mimetypes[ext]
				path = utils.refpath(new_path, options['opf_path'])
				el = E.item(dict({'id': iid, 'href': path, 'media-type': mimetype}))
				if self.fallbacks.get(iid):
					el.attrib['fallback'] = self.fallbacks[iid]
				if self.is_epub3():
					props = self.get_properties(iid)
					if props:
						el.attrib['properties'] = ' '.join(props)
				manifest.append(el)
				fp.close()

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
				iid = self.add_resource(toc_path, openfunc=output.open, load=False)
				self.set_property(iid, 'nav')

		with self.export_opf(options=options) as fp:
			output.writestr(options['opf_path'], fp.read(), zipfile.ZIP_DEFLATED)

		for res_type, values in self.manifest.items():
			for iid in values:
				path, fp, mimetype = self.open(iid)
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
