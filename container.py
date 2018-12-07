
import utils
import re
from lxml import etree
from lxml.builder import ElementMaker
import zipfile
from urllib.parse import urlparse
from collections import defaultdict

class epubContainer:
	namespaces = dict(
		c='urn:oasis:names:tc:opendocument:xmlns:container',
		xenc='http://www.w3.org/2001/04/xmlenc#',
		ds='http://www.w3.org/2000/09/xmldsig#'
	)
	rootdir = 'META-INF'
	obfuscation_uris = {
		'http://www.idpf.org/2008/embedding': 'idpf',
		'http://ns.adobe.com/pdf/enc#RC': 'adobe'
	}
	def __init__(self):
		self.rootfiles = []
		self.encryption = {}
		self.obfuscation = {}
		self.signatures = []

	def load_epub(self, epub):
		rootfiles = self.load_container(epub)
		decryptor, obfuscated = self.load_encryption(epub)
		verifier = self.load_signatures(epub)
		return rootfiles, obfuscated, decryptor, verifier

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
			return None, {}

		obfuscated = {}
		tree = etree.parse(epub.open(enc_path))

		for enc_data in tree.findall('{%s}EncryptedData' % self.namespaces['xenc']):
			method, ref = epubDecryptor.get_reference(enc_data)
			if not ref: continue
			if method in self.obfuscation_uris:
				obfuscated[ref] = method
				tree.remove(enc_data)

		decryptor = epubDecryptor()
		decryptor.load_epub(tree, epub)
		return decryptor, obfuscated

	def load_signatures(self, epub):
		ds_path = self.rootdir+'/signatures.xml'
		signatures = []

		if not ds_path in epub.namelist():
			return signatures
		tree = etree.parse(epub.open(ds_path))
		for sign in tree.findall('{%s}Signature' % self.namespaces['ds']):
			references = []
			refs = sign.xpath(
				'ds:SignedInfo/ds:Reference[@URI]/@URI', namespaces=self.namespaces)
			refs += sign.xpath(
				'ds:Object/ds:Manifest/ds:Reference[@URI]/@URI', namespaces=self.namespaces)
			for ref in refs:
				url = urlparse(ref)
				if url.netloc or url.scheme: continue
				if not url.path: continue
				references.append(url.path)
			signatures.append((sign, references))
		return signatures

	def set_encryption(self, path, mode='binary', method='aes256'):
		self.encryption[path] = (mode, method)

	def set_obfuscation(self, path, method=''):
		method = method or 'http://www.idpf.org/2008/embedding'
		self.obfuscation[path] = method

	def add_signature(self, pvtkey, method='rsa-sha1', c14n='exc-c14n', 
		digest='sha1', transforms=[]):
		signer = epubSigner(pvtkey, method=method, c14n=c14n, digest=digest, transforms=transforms)
		self.signatures.append(signer)

	def sign(self, path, index=-1, mode='binary', digest='sha1', transforms=[]):
		if not self.signatures:
			self.add_signature(pvtkey)
		signer = self.signatures[index]
		signer.sign(path, mode=mode, digest=digest, transforms=transforms)

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

		if self.encryption or self.obfuscation:
			E = ElementMaker(namespace=xmlns, nsmap=self.namespaces)
			encryption = E.encryption()
			key_count = 0
			for enc_data in self.encryption.values():
				for enc_key in enc_data.xpath('//xenc:EncryptedKey', 
					namespaces=self.namespaces):
					key_count += 1
					key_id = enc_key.get('Id') or ('EK' + str(key_count))
					enc_key.set('Id', key_id)
					enc_key.getparent().replace(
						enc_key, E.RetrievalMethod(dict(URI='#'+key_id,
							Type='http://www.w3.org/2001/04/xmlenc#EncryptedKey')
						)
					)
					encryption.append(enc_key)
				encryption.append(enc_data)

			for path in self.obfuscation:
				enc_data = E.EncryptedData(
					E.EncryptionMethod({'Algorithm': 'http://www.idpf.org/2008/embedding'}),
					E.CipherData(E.CipherReference({'URI': path}))
				)
				encryption.append(enc_data)

			yield self.rootdir+'/encryption.xml', etree.tostring(
				encryption, encoding='utf-8', xml_declaration=True)

		if self.signatures:
			E = ElementMaker(namespace=xmlns, 
				nsmap={None: xmlns, 'ds': self.namespaces['ds']})
			signatures = E.signatures()
			for signer in self.signatures:
				signatures.append(signer.template)
			yield self.rootdir+'/signatures.xml', etree.tostring(
				signatures, encoding='utf-8', xml_declaration=True)

