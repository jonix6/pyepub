
import re
import os
import zipfile
import utils

from publication import epubPackage
from container import epubContainer

from io import BytesIO

from lxml import etree

class epubReader:
	def __init__(self, path):
		self.epub = zipfile.ZipFile(path, 'r')
		assert self.epub.read('mimetype') == utils.MIMETYPE

		self.rootfiles, self.decryptor, self.verifier = epubContainer.load_epub(self.epub)
		assert self.rootfiles

		rootfile = self.rootfiles[0]
		self.load(rootfile)

	def is_encrypted(self):
		return not (not self.decryptor or not self.decryptor.encryption)

	def is_epub3(self):
		return self.package.is_epub3()

	def verify(self, key_data, format='PEM', from_cert=False):
		if not self.verifier: return True
		key = self.verifier.load_publickey(key_data, format=format, from_cert=from_cert)
		return self.verifier.verify_epub(key)

	def set_decrypt_key(self, key_data, format='PEM', asymm=True):
		if not self.decryptor: return
		if asymm:
			key = self.decryptor.load_privatekey(key_data, format=format)
		else:
			key = self.decryptor.load_symmkey(key_data, method=format)
		self.decryptor.key = key

	def open(self, path, key=None):
		if self.decryptor:
			data = self.decryptor.decrypt_epub(path, key=key)
			if data: return BytesIO(data)
			return
		return self.epub.open(path, pwd=key)

	def close(self):
		self.epub.close()

	def read(self, path, key=None):
		fp = self.open(path, key=key)
		if fp:
			data = fp.read()
			fp.close()
			return data

	def load(self, rootfile):
		self.package = epubPackage()
		self.package.load_package(self, rootfile)
		if self.decryptor:
			self.decryptor.uid = self.get_uid()

	def get_uid(self):
		return self.package.uid.value

	def get_title(self, sep=' - '):
		titles = self.package.get_metadata('title')
		if not titles:
			return ''
		return sep.join(titles)

	def get_credits(self, lang='en'):
		credits = {}
		lang_order = ['en', 'cn']
		for creator, prop in self.package.metadata['creator']:
			role = prop.get('role', 'aut')
			roles = utils.marc_codes.get(role, utils.marc_codes['oth'])
			role = roles[lang_order.index(lang)]
			credits[role] = creator
		return credits

	def num_docs(self, linear_only=False):
		return len([x for x in self.package.spine if x[1] or not linear_only])

	def iter_doc(self, linear_only=False):
		for docid, linear, props in self.package.spine:
			if not linear and linear_only:
				continue
			yield self.package.open(docid)

	def iter_toc(self, max_depth=3):
		for content, href, depth in self.package.nav.toc:
			if depth > max_depth: continue
			yield (content, href, depth)

	def get_pagelist(self):
		return self.package.nav.pagelist

	def navigate_to(self, index):
		label, href, depth = self.package.nav.get(index)
		path, *anchor = href.split('#')
		doc = etree.parse(self.open(path))
		return doc

	def navigate_by_text(self, pattern):
		index = self.package.nav.search(pattern)
		if index is None: return
		return self.navigate_to(index)

if __name__ == '__main__':
	reader = epubReader('childrens-literature.epub')
	# for doc in reader.iter_toc(max_depth=2):
	# 	print(doc)
	print(reader.navigate_by_text('the real princess'))
	# for doc in reader.iter_doc():
	# 	print(doc)
	# package = reader.load()
	# # package.add_document('wasteland-content.xhtml')
	# package.version = '3.2'
	# # with package.export_opf() as fp:
	# # 	print(fp.read().decode('utf-8'))
	# # package.version = '2.0'
	# package.export_epub('new.epub')
	reader.close()
