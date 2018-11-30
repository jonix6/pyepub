
import zipfile
import xmlsec
from lxml import etree
import binascii

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
	def __init__(self, epub, key):
		self.epub = epub
		self.key = None
		self.load_key(key)

	def load_key(self, kio, pkcs8=False, format='PEM', cert=False):
		if isinstance(kio, str):
			kio = open(kio, 'rb')
		constant = 'KeyDataFormat'
		if cert:
			constant += 'Cert'
		elif pkcs8:
			constant += 'Pkcs8'
		constant += format.capitalize()
		self.key = xmlsec.Key.from_file(kio, 
			getattr(consts, constant, consts.KeyDataFormatUnknown))

	def load_cert(self, certio, format='PEM'):
		if not self.key:
			return
		if isinstance(certio, str):
			kio = open(certio, 'rb')
		constant = 'KeyDataFormatCert' + format.capitalize()
		self.key.load_cert_from_file(certio, 
			getattr(consts, constant, consts.KeyDataFormatUnknown))

class epubEncryptor(epubSecurityDevice):
	def __init__(self, epub, key):
		epubSecurityDevice.__init__(self, epub, key)
		self.method = 'aes256'
		self.key_method = 'rsa-oaep'
		self.wrap_method = ''
		self.root = etree.Element('{%s}encryption' % self.NSMAP[None], nsmap=self.NSMAP)
		self.references = []

	def build_encryption(self, enc_type=None):
		enc_type = EncryptionType.get(enc_type)

		'''
		<EncryptedData Type="">
			<EncryptionMethod Algorithm="" />
			<CipherData><CipherValue/></CipherData>
		</EncryptedData>
		'''
		assert self.method in EncryptionMethod
		method = EncryptionMethod[self.method]
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
		if self.wrap_method:
			assert self.wrap_method in KeyWrapMethod
			wrap_method = KeyWrapMethod[self.wrap_method]
			enc_key = xmlsec.template.add_encrypted_key(keyinfo, wrap_method)
			xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)
			keyinfo = xmlsec.template.encrypted_data_ensure_key_info(enc_key)

		assert self.key_method in KeyTransportMethod
		key_method = KeyTransportMethod[self.key_method]
		enc_key = xmlsec.template.add_encrypted_key(keyinfo, key_method)
		xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)
		return enc_data

	def make_context(self):
		manager = xmlsec.KeysManager()
		manager.add_key(self.key)

		klass, size = EncryptionKeyType[self.method]
		key = xmlsec.Key.generate(klass, size, consts.KeyDataTypeSymmetric)
		ctx = xmlsec.EncryptionContext(manager)
		if self.wrap_method:
			assert self.wrap_method in KeyWrapMethod
			klass, size = EncryptionKeyType[self.wrap_method]
			_key = xmlsec.Key.generate(klass, size, consts.KeyDataTypeSymmetric)
			manager.add_key(_key)
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

	def encrypt_epub(self, outpath):
		output = zipfile.ZipFile(outpath, 'w')

		encrypted = set()
		for ref in self.references:
			path, *anchor = ref.split('#')
			if not path in self.epub.namelist():
				continue
			fp = self.epub.open(path)
			enc_data = self.encrypt_binary(fp.read())
			cipher_value = enc_data.find('xenc:CipherData/xenc:CipherValue', 
				namespaces=self.NSMAP)
			data = binascii.a2b_base64(cipher_value.text)
			output.writestr(path, data, zipfile.ZIP_DEFLATED)
			cipher_ref = etree.Element('{%s}CipherReference' % self.NSMAP['xenc'])
			cipher_ref.attrib['URI'] = path
			cipher_value.getparent().replace(cipher_value, cipher_ref)
			self.root.append(enc_data)
			encrypted.add(path)

		output.writestr('META-INF/encryption.xml', 
			etree.tostring(self.root, encoding='utf-8', 
				xml_declaration=True, pretty_print=True), 
			zipfile.ZIP_DEFLATED)

		for info in self.epub.infolist():
			path = info.filename
			if path in encrypted: continue
			output.writestr(info, self.epub.read(path), zipfile.ZIP_DEFLATED)

		output.close()

class epubDecryptor(epubSecurityDevice):
	rootpath = 'META-INF/encryption.xml'
	def __init__(self, epub, key):
		epubSecurityDevice.__init__(self, epub, key)
		self.references = {}
		self.load_references()

	def load_references(self):
		with self.epub.open(self.rootpath) as fp:
			root = etree.parse(fp).getroot()
		xmlsec.tree.add_ids(root, root.xpath('//*[@Id]/@Id'))
		for enc_data in root.findall('{%s}EncryptedData' % self.NSMAP['xenc']):
			ref = enc_data.find(
				'xenc:CipherData/xenc:CipherReference', 
				namespaces=self.NSMAP)
			if ref is None: continue
			self.references[ref.get('URI')] = enc_data

	def decrypt(self, enc_data):
		manager = xmlsec.KeysManager()
		manager.add_key(self.key)

		ctx = xmlsec.EncryptionContext(manager)
		return ctx.decrypt(enc_data)

	def decrypt_data(self, path):
		enc_data = self.references[path]
		ref = enc_data.find(
			'xenc:CipherData/xenc:CipherReference', 
			namespaces=self.NSMAP)
		buff = binascii.b2a_base64(self.epub.read(path))
		cipher_value = etree.Element('{%s}CipherValue' % self.NSMAP['xenc'])
		cipher_value.text = buff
		ref.getparent().replace(ref, cipher_value)
		return self.decrypt(enc_data)

	def decrypt_epub(self, outpath):
		output = zipfile.ZipFile(outpath, 'w')

		decrypted = set()
		for ref in self.references:
			if not ref in self.epub.namelist():
				continue
			data = self.decrypt_data(ref)
			output.writestr(ref, data, zipfile.ZIP_DEFLATED)
			decrypted.add(ref)

		for info in self.epub.infolist():
			path = info.filename
			if path == self.rootpath:
				continue
			if path in decrypted: continue
			output.writestr(info, self.epub.read(path), zipfile.ZIP_DEFLATED)

		output.close()

class epubSigner(epubSecurityDevice):
	NSMAP = {
		None: 'urn:oasis:names:tc:opendocument:xmlns:container'
	}
	def __init__(self, epub=None):
		self.method = 'rsa-sha1'
		self.c14n_method = 'exc-c14n'
		self.digest_method = 'sha1'
		self.transforms = ['enveloped']

	def build_signature(self, node, use_cert=False):
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

		'''
		<KeyInfo>
			<X509Data><X509Certificate/></X509Data>
			<KeyValue/>
		</KeyInfo>
		'''
		keyinfo = xmlsec.template.ensure_key_info(sign)
		if use_cert:
			x509 = xmlsec.template.add_x509_data(keyinfo)
			xmlsec.template.x509_data_add_certificate(x509)
		else:
			xmlsec.template.add_key_value(keyinfo)
		
		return sign

	def sign(self, root, use_cert=False):
		sign_node = self.build_signature(root, use_cert=use_cert)
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
