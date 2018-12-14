
import re
from html import escape
from lxml import etree
import copy
import utils

doc_loaders = {
	'head/link[@rel="stylesheet"]': 'href',
	'body//map/area': 'href',
	'body//img': 'src',
	'body//audio|body//video': 'src',
	'body//audio/source|body//video/source': 'src',
	'//script[@src]': 'src'
}

class contentDocs:
	xmlns = 'http://www.w3.org/1999/xhtml'
	NSMAP = dict(
		epub = 'http://www.idpf.org/2007/ops',
		pls = 'https://www.w3.org/2005/01/pronunciation-lexicon',
		ssml = 'https://www.w3.org/2001/10/synthesis'
	)
	DOCTYPE = '<!DOCTYPE html>'
	DOCTYPE4 = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">'

	def __init__(self):
		self.spine = []
		self.reset()

	def reset(self):
		for path, fp in self.spine:
			fp.close()
		self.spine = []
		self.resources = {}
		self.toc = []

	def close(self):
		for path, fp in self.spine:
			fp.close()

	def load_package(self, package, reset=True):
		if reset:
			self.reset()
		self.toc += package.nav.toc
		for idref, linear, prop in package.spine:
			path = package.idmap[idref]
			fp, _ = package.open(idref)
			self.spine.append((path, fp))

	def insert(self, index, path, openfunc=None):
		if openfunc:
			fp = openfunc(path)
		else:
			fp = open(path, 'rb')
		self.spine.insert(index, (path, fp))

	def append(self, path, openfunc=None):
		self.insert(-1, path, openfunc=openfunc)

	def iterparse(self, html=False):
		for path, fp in self.spine:
			doc = etree.iterparse(fp, html=html, events=('start', 'end', 'start-ns'), remove_blank_text=True, resolve_entities=False, recover=True)
			in_body = False
			nsmap = {}
			for event, el in doc:
				if event == 'start-ns':
					prefix, uri = el
					nsmap[uri] = prefix
					continue

				qname = etree.QName(el)
				tag = qname.localname
				namespace = qname.namespace or self.xmlns
				prefix = self.NSMAP.get(namespace, nsmap.get(namespace))
				if prefix: tag = prefix + ':' + tag
				if tag == 'html':
					assert not in_body
					if event == 'end':
						yield 'end_document', (path,)
						break
					yield 'start_document', (path,)
					continue
				if tag == 'head':
					assert not in_body
					if event == 'end':
						yield 'document_head', (el,)
					continue
				attrs = dict(el.attrib)
				if tag == 'body':
					in_body = event == 'start'
					if not in_body:
						tail = (el.tail or '').rstrip()
						yield 'end_element', (tag, attrs, tail)
						el.clear()
				if not in_body:
					continue
				if event == 'start':
					text = (el.text or '').lstrip()
					yield 'start_element', (tag, attrs, text)
				else:
					tail = (el.tail or '').rstrip()
					yield 'end_element', (tag, attrs, tail)
					el.clear()
			del doc

class contentDocHandler:
	def handle(self, iterator):
		for event, args in iterator:
			yield self.call(event, args)

	def call(self, event, args):
		func = getattr(self, event, None)
		if not func: return event, args
		return func(*args)

class contentDocParser(contentDocHandler):
	def __init__(self):
		self.metadata = {}
		self.sheets = set()
		self.scripts = set()
		self.resources = set()
		self.urls = set()
		self.curpath = ''

	def handle(self, iterator):
		for event, args in iterator:
			self.call(event, args)
			yield event, args

	def start_document(self, path):
		self.curpath = path

	def document_head(self, head):
		for meta in head.xpath('meta[@name]'):
			name, content = meta.get('name'), meta.get('content')
			self.metadata[name] = content
		for link in head.findall('link'):
			rel = link.get('rel').split(' ')
			href = link.get('href')
			if 'stylesheet' in rel:
				self.sheets.add(utils.realpath(href, self.curpath))
		for script in head.findall('script'):
			src = script.get('src')
			if not src: continue
			self.scripts.add(utils.realpath(src, self.curpath))

	def start_element(self, tag, attrs, text):
		href = attrs.get('href')
		if href: self.urls.add(utils.realpath(href, self.curpath))
		src = attrs.get('src')
		if src:
			src = utils.realpath(src, self.curpath)
			if tag == 'script':
				self.scripts.add(src)
			else:
				self.resources.add(src)

class contentDocWriter(contentDocHandler):
	xmlns = 'http://www.w3.org/1999/xhtml'
	NSMAP = {
		'http://www.w3.org/XML/1998/namespace': 'xml',
		'http://www.idpf.org/2007/ops': 'epub',
		'https://www.w3.org/2005/01/pronunciation-lexicon': 'pls',
		'https://www.w3.org/2001/10/synthesis': 'ssml'
	}
	def __init__(self, output):
		self.enclosing = ''
		self.output = output

	def start_document(self, path):
		self.output.write('<?xml version="1.0" ?>')
		self.output.write('<!DOCTYPE html>')
		self.output.write('<html xmlns="http://www.w3.org/1999/xhtml"')
		for uri, prefix in self.NSMAP.items():
			self.output.write(' xmlns:%s="%s"' % (prefix, uri))
		self.output.write('>')

	def document_head(self, head):
		self.output.write(
			etree.tostring(head, encoding='utf-8').decode('utf-8')
		)

	def start_element(self, tag, attrs, text):
		content = ''
		if self.enclosing:
			content += '>'
			self.enclosing = ''
		content += '<' + tag
		for k, v in attrs.items():
			qname = etree.QName(k)
			if qname.namespace:
				k = self.NSMAP[qname.namespace] + ':' + qname.localname
			content += ' %s="%s"' % (k, v)
		if text:
			content += '>' + escape(text)
		else:
			self.enclosing = tag
		self.output.write(content)

	def end_element(self, tag, attrs, tail):
		if self.enclosing:
			content = '/>' + escape(tail)
			self.enclosing = ''
		else:
			content = '</' + tag + '>' + escape(tail)
		self.output.write(content)

	def end_document(self, path):
		self.output.write('</html>')
		self.output.close()

def pipe(iterator, *handlers):
	wrapper = iterator
	for handler in handlers:
		wrapper = handler.handle(wrapper)
	return wrapper

if __name__ == '__main__':
	from urllib.request import urlopen
	doc = contentDocs()
	doc.append('wasteland-content.xhtml')
	# doc.append('https://www.gzebook.cn', openfunc=urlopen)
	output = open('new.xhtml', 'w', encoding='utf-8')
	writer = contentDocWriter(output)
	parser = contentDocParser()
	wrapper = pipe(doc.iterparse(), parser, writer)
	for x in wrapper:
		continue
	doc.close()
	print(parser.metadata, parser.sheets, parser.scripts, parser.resources, parser.urls)