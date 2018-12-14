
import zipfile
from collections import defaultdict, OrderedDict

from container import epubContainer
from publication import epubPackage, epubNav
from contentdocs import contentDocs
import utils

class epubExportOptions:
	version = '3.2'
	opf_path = 'OEBPS/content'
	toc_path = 'OEBPS/nav'
	resource_dir = {
		'document': 'OEBPS/Text',
		'image': 'OEBPS/Images',
		'stylesheet': 'OEBPS/Styles',
		'font': 'OEBPS/Font',
		'script': 'OEBPS/Scripts',
		'other': 'OEBPS/Misc'
	}
	with_ext = True
	hash_name = False
	encryption = defaultdict(set)
	signature = defaultdict(set)


class epubWriter:
	def __init__(self):
		# global attributes
		self.container = epubContainer()
		self.packages = OrderedDict()

		self.encrypt_key = None
		self.sign_key = None

		self.options = epubExportOptions()
		self.metadata = defaultdict(list)

	def add_package(self, package, scheme='', overwrite=False):
		if isinstance(package, epubPackage):
			uid = package.uid.value
		elif isinstance(package, str):
			uid = package
			package = epubPackage()
		else:
			return
		if uid in self.packages and not overwrite:
			return self.packages[uid]
		self.packages[uid] = package
		if scheme:
			package.set_metadata('identifier', uid, {'scheme': scheme})
		return package

	def load_epub(self, epub, overwrite=False):
		rootfiles, decryptor, verifier = epubContainer.load_epub(epub)
		assert not decryptor
		for rootfile in rootfiles:
			package = epubPackage()
			package.load_package(epub, rootfile)
			package = self.add_package(package, overwrite=overwrite)

	def set_encrypt_key(self, key_data, format='PEM', asymm=True, from_cert=False):
		if asymm:
			key = self.container.encryptor.load_publickey(key_data, format=format, from_cert=from_cert)
		else:
			key = self.container.encryptor.load_symmkey(key_data, method=format)
		self.encrypt_key = key

	def set_sign_key(self, pvtkey, format='PEM'):
		key = self.container.signer.load_privatekey(key_data, method=format)
		self.sign_key = key

	def dump_package(self, package):
		for uid in package.idmap:
			path, fp, mimetype = package.open(uid)
			yield uid, path, fp, mimetype

	def export_package(self, output):
		for package in self.packages:
			for data, path, mimetype in package.export(self.options):
				if path in self.container.encryption:
					data = self.container.encrypt(data, key)
				output.writestr(data, path, zipfile.ZIP_DEFLATED)



if __name__ == '__main__':
	import sys
	writer = epubWriter()
	epub = zipfile.ZipFile('childrens-literature.epub', 'r')
	writer.load_epub(epub)
	print(writer.packages)
	epub.close()
	sys.exit()

	writer = epubWriter()
	package = writer.add_package('978123456789', 'isbn')
	package.add_document('01.xhtml')
	package.add_document('02.xhtml')
	package.nav.set_builder(builder)

	package.set_title('test book')
	package.add_author('test author')
	package.add_author('test translater', role='translater')
	with open('rsacert.pem', 'rb') as fp:
		writer.set_encrypt_key(fp.read(), from_cert=True)
	with open('rsakey.pem', 'rb') as fp:
		writer.set_sign_key(fp.read())

	package.cover = 'cover'
	package.version = '3.2'
	writer.save('output.epub')
