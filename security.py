
import re
import os
import copy
import binascii
from hashlib import sha1
from tempfile import NamedTemporaryFile, mkdtemp
from shutil import rmtree

from lxml import etree
import xmlsec

consts = xmlsec.constants

EncryptionType = {
	'element': consts.TypeEncElement,
	'content': consts.TypeEncContent,
}

EncryptionMethod = {
	'des3': consts.TransformDes3Cbc,
	'aes128': consts.TransformAes128Cbc,
	'aes192': consts.TransformAes192Cbc,
	'aes256': consts.TransformAes256Cbc
}

KeyTransportMethod = {
	'rsa-oaep': consts.TransformRsaOaep,
	'rsa-pkcs1': consts.TransformRsaPkcs1
}

KeyWrapMethod = {
	'des3': consts.TransformKWDes3,
	'aes128': consts.TransformKWAes128,
	'aes192': consts.TransformKWAes192,
	'aes256': consts.TransformKWAes256
}

EncryptionKeyType = {
	'des3': (consts.KeyDataDes, 192),
	'aes128': (consts.KeyDataAes, 128),
	'aes192': (consts.KeyDataAes, 192),
	'aes256': (consts.KeyDataAes, 256)
}

SignatureMethod = {
	'dsa-sha1': consts.TransformDsaSha1,
	'rsa-md5': consts.TransformRsaMd5,
	'rsa-sha1': consts.TransformRsaSha1,
	'rsa-sha224': consts.TransformRsaSha224,
	'rsa-sha256': consts.TransformRsaSha256,
	'rsa-sha384': consts.TransformRsaSha384,
	'rsa-sha512': consts.TransformRsaSha512,
	'rsa-ripemd160': consts.TransformRsaRipemd160,
	'ecdsa-sha1': consts.TransformEcdsaSha1,
	'ecdsa-sha224': consts.TransformEcdsaSha224,
	'ecdsa-sha256': consts.TransformEcdsaSha256,
	'ecdsa-sha384': consts.TransformEcdsaSha384,
	'ecdsa-sha512': consts.TransformEcdsaSha512
}

DigestMethod = {
	'md5': consts.TransformMd5,
	'sha1': consts.TransformSha1,
	'sha224': consts.TransformSha224,
	'sha256': consts.TransformSha256,
	'sha384': consts.TransformSha384,
	'sha512': consts.TransformSha512,
	'ripemd160': consts.TransformRipemd160
}

CanonicalizationMethod = {
	'c14n': consts.TransformInclC14N,
	'c14n#': consts.TransformInclC14N11WithComments,
	'c14n11': consts.TransformInclC14N11,
	'c14n11#': consts.TransformInclC14N11WithComments,
	'exc-c14n': consts.TransformExclC14N,
	'exc-c14n#': consts.TransformExclC14NWithComments
}

TransformMethod = dict({
	'xpath': consts.TransformXPath,
	'xpath2': consts.TransformXPath2,
	'xslt': consts.TransformXslt,
	'enveloped': consts.TransformEnveloped
}, **CanonicalizationMethod)


class epubSecurityDevice:
	NSMAP = {
		None: 'urn:oasis:names:tc:opendocument:xmlns:container',
		'xenc': 'http://www.w3.org/2001/04/xmlenc#',
		'ds': 'http://www.w3.org/2000/09/xmldsig#'
	}

	@classmethod
	def load_publickey(self, buff, format='PEM', from_cert=False):
		constant = 'KeyDataFormat'
		if from_cert:
			constant += 'Cert'
		constant += format.capitalize()
		publickey = xmlsec.Key.from_memory(buff, getattr(consts, constant, consts.KeyDataFormatUnknown))
		return publickey

	@classmethod
	def load_privatekey(self, buff, format='PEM'):
		constant = 'KeyDataFormat'
		# if pkcs8:
		# 	constant += 'Pkcs8'
		constant += format.capitalize()
		privatekey = xmlsec.Key.from_memory(buff, format=getattr(consts, constant, consts.KeyDataFormatUnknown))
		return privatekey

	@classmethod
	def load_x509_cert(self, key, buff, format='PEM'):
		constant = 'KeyDataFormatCert' + format.capitalize()
		key.load_cert_from_memory(buff, 
			getattr(consts, constant, consts.KeyDataFormatUnknown))

	@classmethod
	def load_symmkey(self, buff, method='aes256'):
		assert method in EncryptionMethod
		key_format, key_size = EncryptionKeyType[method]
		buff = buff[:key_size]
		if len(buff) * 8 < key_size:
			n = key_size // 8 - len(buff)
			buff += n.to_bytes(1, 'big') * n
		key = xmlsec.Key.from_binary_data(key_format, buff)
		return key

	@classmethod
	def read_publickey(self, path, format='PEM', from_cert=False):
		fp = open(path, 'rb')
		buff = fp.read()
		fp.close()
		return self.load_publickey(buff, format=format, from_cert=from_cert)

	@classmethod
	def read_privatekey(self, path, format='PEM'):
		fp = open(path, 'rb')
		buff = fp.read()
		fp.close()
		return self.load_privatekey(buff, format=format)

	@classmethod
	def read_x509_cert(self, key, path, format='PEM'):
		fp = open(path, 'rb')
		buff = fp.read()
		fp.close()
		return self.load_x509_cert(key, buff, format=format)

	@classmethod
	def idpf_obfuscation(self, data, uid):
		key = sha1(re.sub(r'\s', '', uid).encode('utf-8')).digest()

		chunk = data[:1040]
		outer = 0
		obfuscated = bytearray()
		while outer < 52:
			inner = 0
			while inner < 20:
				index = outer*20+inner
				if index >= len(chunk): break
				sourceByte = chunk[index]
				keyByte = key[inner]
				obfuscated.append(sourceByte ^ keyByte)
				inner += 1
			outer += 1
		return obfuscated+data[1040:]

	@classmethod
	def adobe_obfuscation(self, data, uid):
		key = re.sub(r'(?:urn:uuid:)?(.*)', r'\1', uid)
		key = re.sub(r'[^0-9A-Fa-f]', '', key).encode('utf-8')
		key = binascii.unhexlify((key + key)[:32])
		chunk = data[:1024]
		outer = 0
		obfuscated = bytearray()
		while outer < 32:
			inner = 0
			while inner < 32:
				index = outer*32+inner
				if index >= len(chunk): break
				sourceByte = chunk[index]
				keyByte = key[inner]
				obfuscated.append(sourceByte ^ keyByte)
				inner += 1
			outer += 1
		return obfuscated+data[1024:]


class epubEncryptor(epubSecurityDevice):
	def __init__(self):
		self.root = etree.Element('{%s}encryption' % self.NSMAP[None], nsmap=self.NSMAP)
		self.wrapped_keys = []
		self.publickey = None
		
	def make_enc_data(self, method='aes256', mode='binary'):
		enc_type = EncryptionType.get(mode)
		assert method in EncryptionMethod
		method = EncryptionMethod[method]
		enc_data = xmlsec.template.encrypted_data_create(
			self.root, type=enc_type, method=method
		)
		xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
		return copy.copy(enc_data)

	@classmethod
	def make_keyinfo(self, node, method, name=''):
		keyinfo = xmlsec.template.encrypted_data_ensure_key_info(node)
		enc_key = xmlsec.template.add_encrypted_key(keyinfo, method)
		if name:
			xmlsec.template.add_key_name(keyinfo, name)
		xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)
		return keyinfo

	@classmethod
	def make_symmkey(self, method, data=b''):
		key_format, key_size = EncryptionKeyType[method]
		if data:
			key_bytes = key_size // 8
			data = data[:key_bytes]
			n = key_bytes - len(data)
			data += n.to_bytes(1, 'big') * n
			key = xmlsec.Key.from_binary_data(key_format, data)
		else:
			key = xmlsec.Key.generate(key_format, key_size, consts.KeyDataTypeSymmetric)
		return key

	def set_publickey(self, pubkey, method='rsa-oaep', 
		format='PEM', from_cert=False, name=''):
		assert method in KeyTransportMethod
		if not isinstance(pubkey, xmlsec.Key):
			pubkey = self.load_publickey(pubkey, format=format, from_cert=from_cert)
		method = KeyTransportMethod[method]
		self.publickey = (pubkey, method, name)

	def wrap_key(self, wrap_method='aes256', key=None, name=''):
		assert wrap_method in KeyWrapMethod
		if not isinstance(key, xmlsec.Key):
			key = self.make_symmkey(wrap_method, data=key)
		method = KeyWrapMethod[wrap_method]
		self.wrapped_keys.append((key, method, name))

	def make_encryption(self, key=None, mode='binary', method='aes256'):
		assert any([self.publickey, self.wrapped_keys, key])
		enc_data = self.make_enc_data(method=method, mode=mode)
		keys = self.wrapped_keys[:]

		if self.publickey:
			keys.append(self.publickey)

		parent = enc_data
		for _, key_method, key_name in keys:
			keyinfo = self.make_keyinfo(parent, key_method, name=key_name)
			parent = keyinfo.find('{%s}EncryptedKey' % self.NSMAP['xenc'])

		manager = xmlsec.KeysManager()
		for subkey, _, __ in keys[::-1]:
			manager.add_key(subkey)

		ctx = xmlsec.EncryptionContext(manager)
		ekey = key
		if not isinstance(ekey, xmlsec.Key):
			ekey = self.make_symmkey(method, data=ekey)
		ctx.key = ekey

		return enc_data, ctx

	def encrypt_file(self, path, key=None, method='aes256'):
		enc_data, ctx = self.make_encryption(key=key, method=method)
		enc_data = ctx.encrypt_uri(enc_data, path)
		return enc_data

	def encrypt_binary(self, data, key=None, method='aes256'):
		enc_data, ctx = self.make_encryption(key=key, method=method)
		enc_data = ctx.encrypt_binary(enc_data, data)
		return enc_data

	def encrypt_xml(self, root, xpath, key=None, method='aes256', xmlns='ns'):
		if not isinstance(key, xmlsec.Key):
			key = self.make_symmkey(method, data=key)
			
		nsmap = root.nsmap.copy()
		if None in nsmap:
			nsmap[xmlns] = nsmap.pop(None)
			
		template, ctx = self.make_encryption(key=key, mode='element', method=method)
		for node in root.xpath(xpath, namespaces=nsmap):
			if node.getparent() is None:
				continue
			_node = copy.copy(node)
			enc_data = ctx.encrypt_xml(template, _node)
			node.getparent().replace(node, enc_data)
			ctx.reset()
			ctx.key = key
		return root

	def encrypt_html(self, root, selector, key=None, method='aes256'):
		if not isinstance(key, xmlsec.Key):
			key = self.make_symmkey(method, data=key)

		template, ctx = self.make_encryption(key=key, mode='element', method=method)
		for elem in root.cssselect(selector):
			if elem.getparent() is None:
				continue
			_elem = copy.copy(elem)
			enc_data = ctx.encrypt_xml(template, _elem)
			elem.getparent().replace(elem, enc_data)
			ctx.reset()
			ctx.key = key
		return root

	@classmethod
	def detach(self, enc_data, path):
		enc_data = copy.copy(enc_data)
		value = enc_data.find('xenc:CipherData/xenc:CipherValue', 
			namespaces={'xenc': self.NSMAP['xenc']})
		if value is None: return
		data = binascii.a2b_base64(value.text)
		ref = etree.Element('{%s}CipherReference' % self.NSMAP['xenc'])
		ref.set('URI', path)
		value.getparent().replace(value, ref)
		return enc_data, data

	@classmethod
	def unbind_key(self, enc_data, keyid):
		_enc_key = xmlsec.tree.find_node(enc_data, consts.NodeEncryptedKey, consts.EncNs)
		if _enc_key is None: return
		enc_key = copy.copy(_enc_key)
		enc_key.set('Id', keyid)
		retrieval = enc_data.makeelement(
			etree.QName(consts.DSigNs, 'RetrievalMethod'), {
				'URI': '#'+keyid, 
				'Type': 'http://www.w3.org/2001/04/xmlenc#EncryptedKey'
			})
		_enc_key.getparent().replace(_enc_key, retrieval)
		return enc_data, enc_key


class XMLDecryptor(epubSecurityDevice):
	@classmethod
	def get_encinfo(self, enc_data):
		enc_type = ['xml', 'binary'][bool(enc_data.get('Type'))-1]
		method = enc_data.xpath('xenc:EncryptionMethod/@Algorithm', 
			namespaces={'xenc': self.NSMAP['xenc']})[0]
		ref_node = enc_data.find('xenc:CipherData/xenc:CipherReference', 
			namespaces={'xenc': self.NSMAP['xenc']})
		ref = ''
		if ref_node is not None:
			ref = ref_node.get('URI')
		return method, ref, enc_type
		
	@classmethod
	def envelop(self, enc_data, data):
		ref = enc_data.find('xenc:CipherData/xenc:CipherReference', 
			namespaces={'xenc': self.NSMAP['xenc']})
		if ref is None: return
		value = etree.Element('{%s}CipherValue' % self.NSMAP['xenc'])
		ref.getparent().replace(ref, value)
		value.text = binascii.b2a_base64(data)

	@classmethod
	def decrypt_binary(self, enc_data, key):
		manager = xmlsec.KeysManager()
		manager.add_key(key)

		ctx = xmlsec.EncryptionContext(manager)
		return ctx.decrypt(enc_data)

	@classmethod
	def decrypt_xml(self, root, key):
		manager = xmlsec.KeysManager()
		manager.add_key(key)

		ctx = xmlsec.EncryptionContext(manager)
		for enc_data in root.xpath('//xenc:EncryptedData', 
			namespaces={'xenc': self.NSMAP['xenc']}):
			elem = ctx.decrypt(copy.copy(enc_data))
			enc_data.getparent().replace(enc_data, elem)
		return root


class epubDecryptor(XMLDecryptor):
	rootfile = 'META-INF/encryption.xml'
	def __init__(self, epub):
		self.epub = epub
		self.encryption = {}
		self.key = None

	def load_encryption(self, root=None):
		if root is None:
			root = etree.parse(self.epub.open(self.rootfile)).getroot()
		ids = root.xpath('//*[@Id]/@Id')
		xmlsec.tree.add_ids(root, ids)
		for enc_data in root.findall('{%s}EncryptedData' % self.NSMAP['xenc']):
			method, uri, enc_type = self.get_encinfo(enc_data)
			self.encryption[uri] = (enc_data, enc_type)

	def decrypt_epub(self, uri, key=None):
		assert isinstance(self.key or key, xmlsec.Key)
		if not uri in self.epub.namelist():
			return
		enc_data, enc_type = self.encryption[uri]
		self.envelop(enc_data, self.epub.read(uri))
		return getattr(self, 'decrypt_' + enc_type)(enc_data, key or self.key)


class epubSigner(epubSecurityDevice):
	def __init__(self):
		self.manifest = []
		self.privatekey = None
		self.root = etree.Element('{%s}signatures' % self.NSMAP[None], 
			nsmap={None: self.NSMAP[None]})

	def set_privatekey(self, pvtkey, method='rsa-sha1', format='PEM', key_name='', reset=True):
		assert method in SignatureMethod
		if not isinstance(pvtkey, xmlsec.Key):
			pvtkey = self.load_privatekey(pvtkey, format=format)
		self.privatekey = (pvtkey, method, key_name)
		if reset:
			self.manifest = []

	def make_signature(self, method='rsa-sha1', c14n_method='exc-c14n', key_name=''):
		assert method in SignatureMethod
		method = SignatureMethod[method]
		assert c14n_method in CanonicalizationMethod
		c14n_method = CanonicalizationMethod[c14n_method]
		
		sign = xmlsec.template.create(self.root, 
			sign_method=method, c14n_method=c14n_method
		)
		keyinfo = xmlsec.template.ensure_key_info(sign)
		xmlsec.template.add_key_value(keyinfo)
		if key_name:
			xmlsec.template.add_key_name(keyinfo, key_name)
		return copy.copy(sign)

	def add_reference(self, parent, uri, binary=False, digest_method='sha1', transforms=[]):
		sign = self.make_signature()
		assert digest_method in DigestMethod
		digest_method = DigestMethod[digest_method]
		ref = xmlsec.template.add_reference(sign, digest_method, 
			uri=uri)
		if not binary:
			for transform in transforms:
				assert transform in TransformMethod
				xmlsec.template.add_transform(ref, TransformMethod[transform])
		parent.append(copy.copy(ref))

	def add_object(self, path, binary=True, 
		digest_method='sha1', transforms=[]):
		self.manifest.append((path, binary, digest_method, transforms))

	def sign(self, sign_id, c14n_method='exc-c14n', digest_method='sha1', transforms=[]):
		assert self.privatekey and self.manifest
		pvtkey, method, key_name = self.privatekey
		dsig = self.make_signature(method=method, c14n_method=c14n_method, 
			key_name=key_name)

		assert digest_method in DigestMethod
		digest_method = DigestMethod[digest_method]
		ref = xmlsec.template.add_reference(dsig, digest_method, uri='#'+sign_id)
		for transform in transforms:
			assert transform in TransformMethod
			xmlsec.template.add_transform(ref, TransformMethod[transform])

		object_node = dsig.makeelement(
			etree.QName(consts.DSigNs, consts.NodeObject))
		manifest_node = dsig.makeelement(
			etree.QName(consts.DSigNs, consts.NodeManifest), {'Id': sign_id})
		object_node.append(manifest_node)
		dsig.append(object_node)

		ctx = xmlsec.SignatureContext()
		ctx.key = pvtkey

		temp_uris = {}
		for uri, sign_binary, sign_digest, sign_transforms in self.manifest:
			if not os.path.isfile(uri):
				continue
			self.add_reference(manifest_node, uri, binary=sign_binary, 
				digest_method=sign_digest, transforms=sign_transforms)

		if not manifest_node.getchildren():
			return

		ctx.sign(dsig)
		return dsig

	def sign_epub(self, epub, sign_id, c14n_method='exc-c14n', 
		digest_method='sha1', transforms=[]):
		assert self.privatekey and self.manifest
		pvtkey, method, key_name = self.privatekey
		dsig = self.make_signature(method=method, c14n_method=c14n_method, 
			key_name=key_name)

		assert digest_method in DigestMethod
		digest_method = DigestMethod[digest_method]
		ref = xmlsec.template.add_reference(dsig, digest_method, uri='#'+sign_id)
		for transform in transforms:
			assert transform in TransformMethod
			xmlsec.template.add_transform(ref, TransformMethod[transform])

		object_node = dsig.makeelement(
			etree.QName(consts.DSigNs, consts.NodeObject))
		manifest_node = dsig.makeelement(
			etree.QName(consts.DSigNs, consts.NodeManifest), {'Id': sign_id})
		object_node.append(manifest_node)
		dsig.append(object_node)

		ctx = xmlsec.SignatureContext()
		ctx.key = pvtkey

		dtemp = mkdtemp()
		for uri, sign_binary, sign_digest, sign_transforms in self.manifest:
			if not uri in epub.namelist(): continue
			self.add_reference(manifest_node, uri, binary=sign_binary, 
				digest_method=sign_digest, transforms=sign_transforms)
			epub.extract(uri, path=dtemp)

		if not manifest_node.getchildren():
			return

		retval = os.getcwd()
		os.chdir(dtemp)
		try:
			ctx.sign(dsig)
		finally:
			os.chdir(retval)
			rmtree(dtemp)

		return dsig


class XMLVerifier(epubSecurityDevice):
	@classmethod
	def get_references(self, sign):
		result = set()
		refs = sign.xpath('ds:SignedInfo/ds:Reference/@URI', 
			namespaces={'ds': self.NSMAP['ds']})
		for ref in refs:
			if not ref: continue
			if not ref.startswith('#'):
				result.add(ref)
				continue
			rid = ref[1:]
			target = sign.xpath('//*[@Id="%s"]' % rid)
			if not target: continue
			target = target[0]
			if target.tag != etree.QName(consts.DSigNs, consts.NodeManifest):
				continue
			for uri in target.xpath('ds:Reference/@URI', namespaces={'ds': self.NSMAP['ds']}):
				if not uri or uri.startswith('#'): continue
				result.add(uri)
		return result

	@classmethod
	def verify(self, sign, key):
		ctx = xmlsec.SignatureContext()
		ctx.key = key
		try:
			ctx.verify(sign)
		except xmlsec.Error:
			return False
		return True
		

class epubVerifier(XMLVerifier):
	rootfile = 'META-INF/signatures.xml'
	def __init__(self, epub):
		self.epub = epub
		self.key = None

	def verify_epub(self, *keys, root=None):
		def verify_each(root, ctx):
			for i, dsig in enumerate(root.findall('{%s}Signature' % self.NSMAP['ds'])):
				for uri in self.get_references(dsig):
					self.epub.extract(uri, path=dtemp)
				ctx.key = self.key or keys[min(i, len(keys)-1)]
				ctx.verify(dsig)
			return True

		assert self.key or keys
		if self.key:
			assert isinstance(self.key, xmlsec.Key)
		elif keys:
			assert all(isinstance(key, xmlsec.Key) for key in keys)

		dtemp = mkdtemp()
		retval = os.getcwd()
		os.chdir(dtemp)

		if root is None:
			root = etree.parse(self.epub.open(self.rootfile)).getroot()

		ctx = xmlsec.SignatureContext()

		try:
			return verify_each(root, ctx)
		except xmlsec.Error:
			return False
		finally:
			os.chdir(retval)
			rmtree(dtemp)
		return True
