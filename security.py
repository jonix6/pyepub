

import xmlsec
from lxml import etree

from io import BytesIO

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
	# 'hmac-sha1': consts.TransformHmacSha1,
	# 'hmac-sha224': consts.TransformHmacSha224,
	# 'hmac-sha256': consts.TransformHmacSha256,
	# 'hmac-sha384': consts.TransformHmacSha384,
	# 'hmac-sha512': consts.TransformHmacSha512,
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
	def load_key_from_file(self, kio, pkcs=1, base64=True):
		form = consts.KeyDataFormatPem if base64 else consts.KeyDataFormatDer
		self.key = xmlsec.Key.from_file(kio, form)

	def load_cert_from_file(self, kio, pkcs=1, base64=True):
		pass

class epubEncryptor(epubSecurityDevice):
	NSMAP = {
		None: 'urn:oasis:names:tc:opendocument:xmlns:container'
	}
	def __init__(self, epub=None):
		self.cipher = 'aes256'
		self.key_cipher = 'rsa-oaep'
		self.wrap_key = False
		self.root = etree.Element('{%s}encryption' % self.NSMAP[None])

	def build_encryption(self, enc_type=None):
		enc_type = EncryptionType.get(enc_type)

		'''
		<EncryptedData Type="">
			<EncryptionMethod Algorithm="" />
			<CipherData><CipherValue/></CipherData>
		</EncryptedData>
		'''
		assert self.cipher in EncryptionMethod
		method = EncryptionMethod[self.cipher]
		enc_data = xmlsec.template.encrypted_data_create(
			self.root, type=enc_type, method=method
		)
		xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)

		'''
		<KeyInfo>
			<EncryptedKey>
				<EncryptionMethod Algorithm="" />
				<CipherData><CipherValue/></CipherData>
			</EncryptedKey>
		</KeyInfo>
		'''
		keyinfo = xmlsec.template.encrypted_data_ensure_key_info(enc_data)
		if self.wrap_key:
			key_method = KeyWrapMethod[self.cipher]
			enc_key = xmlsec.template.add_encrypted_key(keyinfo, key_method)
			xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)
			keyinfo = xmlsec.template.encrypted_data_ensure_key_info(enc_key)

		assert self.key_cipher in KeyTransportMethod
		key_method = KeyTransportMethod[self.key_cipher]
		enc_key = xmlsec.template.add_encrypted_key(keyinfo, key_method)
		xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)
		return enc_data

	def make_context(self):
		manager = xmlsec.KeysManager()
		manager.add_key(self.key)

		klass, size = EncryptionKeyType[self.cipher]
		key = xmlsec.Key.generate(klass, size, consts.KeyDataTypeSymmetric)
		ctx = xmlsec.EncryptionContext(manager)
		if self.wrap_key:
			manager.add_key(key)
		else:
			ctx.key = key
		return ctx

	def encrypt_xml(self, node, enc_type='element'):
		enc_data = self.build_encryption(enc_type=enc_type)
		ctx = self.make_context()
		return ctx.encrypt_xml(enc_data, node)

	def encrypt_binary(self, data):
		enc_data = self.build_encryption()
		ctx = self.make_context()
		return ctx.encrypt_binary(enc_data, data)

class epubDecryptor(epubSecurityDevice):
	def decrypt(self, enc_data):
		manager = xmlsec.KeysManager()
		manager.add_key(self.key)

		ctx = xmlsec.EncryptionContext(manager)
		return ctx.decrypt(enc_data)

class epubSigner(epubSecurityDevice):
	NSMAP = {
		None: 'urn:oasis:names:tc:opendocument:xmlns:container'
	}
	def __init__(self, epub=None):
		self.method = 'rsa-sha1'
		self.c14n_method = 'exc-c14n'
		self.digest_method = 'sha1'
		self.transforms = ['enveloped']
		self.root = etree.Element('{%s}signatures' % self.NSMAP[None])

	def build_signature(self, node):
		'''
		<Signature>
			<CanonicalizationMethod Algorithm=""/>
			<SignatureMethod Algorithm=""/>
			<Reference>
				<DigestMethod Algorithm=""/><DigestValue/>
			</Reference>
		</Signature>
		'''
		assert self.method in SignatureMethod
		method = SignatureMethod[self.method]
		assert self.c14n_method in CanonicalizationMethod
		c14n_method = CanonicalizationMethod[self.c14n_method]
		sign = xmlsec.template.create(node, 
			sign_method=method, c14n_method=c14n_method
		)
		assert self.digest_method in DigestMethod
		digest_method = DigestMethod[self.digest_method]
		ref = xmlsec.template.add_reference(sign, digest_method)
		xmlsec.template.add_transform(ref, consts.TransformEnveloped)
		# for transform_method in self.transforms:
		# 	if not transform_method in TransformMethod:
		# 		continue
		# 	transform_method = TransformMethod[transform_method]
		# 	xmlsec.template.add_transform(ref, transform_method)

		'''
		<KeyInfo>
			<KeyValue/>
		</KeyInfo>
		'''
		keyinfo = xmlsec.template.ensure_key_info(sign)
		keyvalue = xmlsec.template.add_key_value(keyinfo)
		return sign

	def sign(self, root):
		sign_node = self.build_signature(root)
		root.append(sign_node)
		ctx = xmlsec.SignatureContext()
		ctx.key = self.key
		ctx.sign(sign_node)
		return root

	def sign_binary(self, data):
		ctx = xmlsec.SignatureContext()
		ctx.key = self.key
		assert self.method in SignatureMethod
		method = SignatureMethod[self.method]
		sign_node = ctx.sign_binary(data, method)
		return sign_node

class epubVerifier(epubSecurityDevice):
	def verify(self, node):
		ctx = xmlsec.SignatureContext()
		ctx.key = self.key
		sign = xmlsec.tree.find_child(node, consts.NodeSignature)
		ctx.verify(sign)
		return True

	def verify_binary(self, raw, method, sign):
		assert method in SignatureMethod
		method = SignatureMethod[method]
		ctx = xmlsec.SignatureContext()
		ctx.key = self.key
		ctx.verify_binary(raw, method, sign)
		return True

from random import choice
from Crypto.PublicKey import DSA, RSA, ECC
from Crypto.Hash import HMAC
from ecdsa import SigningKey, NIST256p
import OpenSSL

def test_encrypt_xml(path, xpath, enc_type='element', wrap_key=False):
	node = etree.parse(path).xpath(xpath)
	if not node:
		return
	node = node[0]
	device = epubEncryptor()
	device.cipher = choice(list(EncryptionMethod))
	device.key_cipher = choice(list(KeyTransportMethod))
	device.wrap_key = wrap_key
	with open('rsakey.pem', 'rb') as kio:
		device.load_key_from_file(kio)
	with open('encrypted.xml', 'wb') as out:
		out.write(
			etree.tostring(device.encrypt_xml(node, enc_type=enc_type), 
			pretty_print=True, encoding='utf-8', xml_declaration=True)
		)

def test_decrypt_xml(outpath):
	device = epubDecryptor()
	with open('rsakey.pem', 'rb') as kio:
		device.load_key_from_file(kio)
	enc_data = etree.parse('encrypted.xml').getroot()
	with open(outpath, 'wb') as out:
		out.write(
			etree.tostring(device.decrypt(enc_data), 
			pretty_print=True, encoding='utf-8', xml_declaration=True)
		)

def test_encrypt_binary(path, wrap_key=False):
	device = epubEncryptor()
	device.wrap_key = wrap_key
	device.cipher = choice(list(EncryptionMethod))
	device.key_cipher = choice(list(KeyTransportMethod))
	with open('rsakey.pem', 'rb') as kio:
		device.load_key_from_file(kio)
	with open(path, 'rb') as fp:
		data = fp.read()
	with open('encrypted.xml', 'wb') as out:
		out.write(
			etree.tostring(device.encrypt_binary(data), 
			pretty_print=True, encoding='utf-8', xml_declaration=True)
		)

def test_decrypt_binary(outpath):
	device = epubDecryptor()
	with open('rsakey.pem', 'rb') as kio:
		device.load_key_from_file(kio)
	doc = etree.parse('encrypted.xml')
	enc_data = xmlsec.tree.find_child(doc, "EncryptedData", xmlsec.constants.EncNs)
	with open(outpath, 'wb') as out:
		out.write(device.decrypt(enc_data))

def keygen(key_type):
	key_generator = {
		'rsa': lambda: RSA.generate(2048),
		'dsa': lambda: DSA.generate(2048),
		'ecdsa': lambda: ECC.generate(curve='P-256')
		# 'ecdsa': lambda: SigningKey.generate(curve=NIST256p)
	}
	privatekey_generator = {
		'rsa': lambda key: key.export_key(format='PEM'),
		'dsa': lambda key: key.export_key(format='PEM'),
		'ecdsa': lambda key: key.export_key(format='PEM').encode('ascii')
		# 'ecdsa': lambda key: key.to_pem()
	}
	pubkey_generator = {
		'rsa': lambda key: key.publickey().export_key(format='PEM'),
		'dsa': lambda key: key.publickey().export_key(format='PEM'),
		'ecdsa': lambda key: key.public_key().export_key(format='PEM').encode('ascii')
		# 'ecdsa': lambda key: key.get_verifying_key().to_pem()
	}
	key = key_generator[key_type]()
	privatekey = privatekey_generator[key_type](key)
	pubkey = pubkey_generator[key_type](key)
	return pubkey, privatekey

def test_sign(path):
	root = etree.parse(path).getroot()
	device = epubSigner()
	# device.method = choice(list(SignatureMethod))
	device.method = 'ecdsa-sha1'
	device.c14n_method = choice(list(CanonicalizationMethod))
	device.digest_method = choice(list(DigestMethod))
	print(device.method, device.c14n_method, device.digest_method)

	key_type = device.method.split('-')[0]
	pubkey, privatekey = keygen(key_type)
	with open('%s-pubkey.pem' % key_type, 'wb') as out:
		out.write(pubkey)
	with BytesIO(privatekey) as kio:
		device.load_key_from_file(kio)

	with open('%s-signed.xml' % key_type, 'wb') as out:
		out.write(
			etree.tostring(device.sign(root), 
			pretty_print=True, encoding='utf-8', xml_declaration=True)
		)

import os
def test_sign_binary(path):
	device = epubSigner()
	device.method = choice(list(SignatureMethod))
	print(device.method)

	key_type = device.method.split('-')[0]
	pubkey, privatekey = keygen(key_type)
	with open('%s-pubkey.pem' % key_type, 'wb') as out:
		out.write(pubkey)
	with BytesIO(privatekey) as kio:
		device.load_key_from_file(kio)
	with open(path, 'rb') as fp:
		data = fp.read()
	name = os.path.basename(path)
	with open(device.method + '-' + name, 'wb') as out:
		out.write(device.sign_binary(data))

def test_verify(key_type):
	device = epubVerifier()
	with open(key_type + '-pubkey.pem', 'rb') as kio:
		device.load_key_from_file(kio)
	sign = etree.parse(key_type + '-signed.xml').getroot()
	print(device.verify(sign))

def test_verify_binary(method, path):
	device = epubVerifier()
	key_type = method.split('-')[0]
	with open(key_type + '-pubkey.pem', 'rb') as kio:
		device.load_key_from_file(kio)
	with open(method + '-' + path, 'rb') as fp:
		sign = fp.read()
	with open(path, 'rb') as fp:
		raw = fp.read()
	print(device.verify_binary(raw, method, sign))

# test_encrypt_xml('wasteland-content.xhtml', '*[local-name()="body"]', wrap_key=True)
test_sign('wasteland-content.xhtml')
# test_decrypt_xml('decrypted-content.xhtml')
# test_verify('rsa')
# test_encrypt_binary('cover.jpg')
# test_sign_binary('cover.jpg')
# test_decrypt_binary('cover1.jpg')
# test_verify_binary('rsa-sha1', 'cover.jpg')
