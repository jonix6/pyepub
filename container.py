
import utils
import re
from lxml import etree
from lxml.builder import ElementMaker
import zipfile
from urllib.parse import urlparse
from collections import defaultdict

from security import epubEncryptor, epubDecryptor, epubSigner, epubVerifier

class epubContainer:
	namespaces = dict(
		c='urn:oasis:names:tc:opendocument:xmlns:container',
		xenc='http://www.w3.org/2001/04/xmlenc#',
		ds='http://www.w3.org/2000/09/xmldsig#'
	)
	rootdir = 'META-INF'
	def __init__(self):
		self.rootfiles = []
		self.encryption = {}
		self.obfuscation = {}
		self.signatures = []

		self.encryptor = epubEncryptor()
		self.signer = epubSigner()

	@classmethod
	def load_epub(self, epub):
		rootfiles = self.load_container(self, epub)
		decryptor = self.load_encryption(self, epub)
		verifier = self.load_signatures(self, epub)
		return rootfiles, decryptor, verifier

	def load_container(self, epub):
		tree = etree.parse(epub.open(self.rootdir+'/container.xml'))
		rootfiles = tree.xpath(
			'c:rootfiles/c:rootfile[@media-type="%s"]/@full-path'
			 % utils.mimetypes['.opf'], 
			namespaces=self.namespaces)
		return rootfiles

	def load_encryption(self, epub):
		enc_path = self.rootdir+'/encryption.xml'
		if not enc_path in epub.namelist():
			return

		tree = etree.parse(epub.open(enc_path))
		decryptor = epubDecryptor(epub)
		decryptor.load_encryption(tree)
		if decryptor.encryption or decryptor.obfuscation:
			return decryptor

	def load_signatures(self, epub):
		ds_path = self.rootdir+'/signatures.xml'

		if not ds_path in epub.namelist():
			return

		tree = etree.parse(epub.open(ds_path))
		verifier = epubVerifier(epub)
		verifier.load_signatures(tree)
		return verifier

	def set_encryption(self, path, outpath='', method='aes256', binary=True):
		outpath = outpath or path
		self.encryption[path] = outpath, method, binary

	def set_obfuscation(self, path, outpath='', method='idpf'):
		outpath = outpath or path
		self.obfuscation[path] = outpath, method

	def add_signature(self, path, binary=True, digest='sha1', transforms=[]):
		self.signatures[path] = binary, digest, transforms

	def encrypt(self, writer):
		for path, (outpath, method, binary) in self.encryption.items():
			mode = ['xml', 'binary'][bool(binary)]
			if binary:
				rawdata = writer.read(path)
			else:
				rawdata = etree.parse(writer.open(path)).getroot()
			enc_method = getattr(self.encryptor, 'encrypt_'+mode, None)
			enc_data = enc_method(data, method=method)
			enc_data, data = self.encryptor.detach(enc_data, outpath)
			self.encryptor.root.append(enc_data)
			yield data, path
		self.encryption.clear()

		uid = writer.get_uid()
		for path, (outpath, method) in self.obfuscation.items():
			rawdata = writer.read(path)
			data = self.encryptor.obfuscate(rawdata, uid, method=method)
			enc_data = self.encryptor.make_obfuscation_node(outpath, method=method)
			self.encryptor.root.append(enc_data)
			yield data, path
		self.obfuscation.clear()

	def sign(self, c14n='exc-c14n', digest='sha1', transforms=[]):
		for path, (binary, digest, transforms) in self.signatures.items():
			self.signer.add_object(path, binary=binary, digest_method=digest, transforms=transforms)
		dsig = self.signer.sign('pyepub-sign', c14n_method=c14n, digest_method=digest, transforms=transforms)
		self.signer.root.append(dsig)

	def export(self):
		xmlns = self.namespaces['c']
		E = ElementMaker(namespace=xmlns, nsmap={None: xmlns})
		rootfiles = E.rootfiles()
		for rootfile in self.rootfiles:
			rootfiles.append(
				E.rootfile({'media-type': utils.mimetypes['.opf'], 'full-path': rootfile})
			) 
		container = E.container({'version': '1.0'}, rootfiles)
		yield self.rootdir+'/container.xml', etree.tostring(
			container, encoding='utf-8', xml_declaration=True)

		if self.encryptor.root.get_children():
			yield self.rootdir+'/encryption.xml', etree.tostring(
				self.encryptor.root, encoding='utf-8', xml_declaration=True)

		if self.signer.root.get_children():
			yield self.rootdir+'/signatures.xml', etree.tostring(
				self.signer.root, encoding='utf-8', xml_declaration=True)

