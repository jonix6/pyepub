
import os
import zipfile
import utils

from package import epubPackage
from container import epubContainer

class epubReader:
	def __init__(self, path):
		self.epub = zipfile.ZipFile(path, 'r')
		assert self.epub.read('mimetype') == utils.MIMETYPE

		self.container = epubContainer()
		self.container.load_container(self.epub)
		assert self.container.rootfiles

	def close(self):
		self.epub.close()

	def load(self, rootfile=''):
		_rootfile, *_ = self.container.rootfiles
		rootfile = rootfile or _rootfile

		package = epubPackage()
		package.load_package(self.epub, rootfile)

		return package

if __name__ == '__main__':
	reader = epubReader('childrens-literature.epub')
	package = reader.load()
	package.add_document('wasteland-content.xhtml')
	# package.version = '3.2'
	# with package.export_opf() as fp:
	# 	print(fp.read().decode('utf-8'))
	package.version = '2.0'
	package.export_epub('new.epub')
	reader.close()
