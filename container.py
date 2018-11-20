
import utils
import re
from lxml import etree
from lxml.builder import ElementMaker

class epubContainer:
	namespaces = dict(
		c = 'urn:oasis:names:tc:opendocument:xmlns:container',
		ds = 'http://www.w3.org/2000/09/xmldsig#',
		dsig11 = 'http://www.w3.org/2009/xmldsig11#',
		dsig2 = 'http://www.w3.org/2010/xmldsig2#',
		ec = 'http://www.w3.org/2001/10/xml-exc-c14n#',
		dsig_more = 'http://www.w3.org/2001/04/xmldsig-more#',
		xenc = 'http://www.w3.org/2001/04/xmlenc#',
		xenc11 = 'http://www.w3.org/2009/xmlenc11#',

		compress = 'http://www.idpf.org/2016/encryption#compression',
		metadata = 'http://www.idpf.org/2013/metadata'
	)
	xmlenc = {
		'http://www.w3.org/2001/04/xmlenc#tripledes-cbc': 'des3',
		'http://www.w3.org/2001/04/xmlenc#aes128-cbc': 'aes128',
		'http://www.w3.org/2001/04/xmlenc#aes192-cbc': 'aes192',
		'http://www.w3.org/2001/04/xmlenc#aes256-cbc': 'aes256',
		'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p': 'rsa_oaep_mgf1',
		'http://www.w3.org/2001/04/xmlenc#rsa-1_5': 'rsa1_5',
		'http://www.w3.org/2001/04/xmlenc#dh': 'dh',
		'http://www.w3.org/2001/04/xmlenc#kw-tripledes': 'des3_kw',
		'http://www.w3.org/2001/04/xmlenc#kw-aes128': 'aes128_kw',
		'http://www.w3.org/2001/04/xmlenc#kw-aes192': 'aes192_kw',
		'http://www.w3.org/2001/04/xmlenc#kw-aes256': 'aes256_kw',
		'http://www.w3.org/2001/04/xmlenc#sha256': 'sha256',
		'http://www.w3.org/2001/04/xmlenc#sha384': 'sha384',
		'http://www.w3.org/2001/04/xmlenc#sha512': 'sha512',
		'http://www.w3.org/2001/04/xmlenc#ripemd160': 'ripemd160',
		'http://www.idpf.org/2008/embedding': 'idpf_obfuscation'
	}
	xmlenc11 = {
		'http://www.w3.org/2009/xmlenc11#aes128-gcm': 'aes128_gcm',
		'http://www.w3.org/2009/xmlenc11#aes192-gcm': 'aes192_gcm',
		'http://www.w3.org/2009/xmlenc11#aes256-gcm': 'aes256_gcm',
		'http://www.w3.org/2009/xmlenc11#ConcatKDF': 'concatkdf',
		'http://www.w3.org/2009/xmlenc11#pbkdf2': 'pbkdf2',
		'http://www.w3.org/2009/xmlenc11#rsa-oaep': 'rsa_oaep',
		'http://www.w3.org/2009/xmlenc11#ECDH-ES': 'ecdh_es',
		'http://www.w3.org/2009/xmlenc11#dh-es': 'dh_es'
	}
	rootdir = 'META-INF'
	def __init__(self):
		self.rootfiles = []
		self.enc_keys = {}
		self.enc_refs = {}

	def load_container(self, epub):
		tree = etree.parse(epub.open(self.rootdir+'/container.xml'))
		self.rootfiles = tree.xpath(
			'c:rootfiles/c:rootfile[@media-type="%s"]/@full-path' % utils.mimetypes['.opf'], 
			namespaces=self.namespaces)

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

	def load_encryption(self, fp):
		tree = etree.parse(fp)
		enc_keys = {}
		for enc_data in tree.findall('{%s}EncryptedData' % self.namespaces['enc']):
			ref = tree.find('xenc:CipherData/xenc:CipherReference', namespaces=self.namespaces)
			if ref is None: continue
			ref = ref.get('URI')
			self.enc_refs[ref] = ()
			alg = enc_data.xpath('enc:EncryptionMethod/@Algorithm', namespaces=self.namespaces)
			keyinfo = enc_data

	def _load_encrypt_key(self, key_node):
		value = key_node.find('xenc:CipherData/xenc:CipherValue/text()', namespaces=self.namespaces)
		alg = enc_data.xpath('enc:EncryptionMethod/@Algorithm', namespaces=self.namespaces)

	def decrypt_des3(self, data, key):
		from Crypto.Cipher import DES3
		cipher = DES3.new(key, mode=DES3.MODE_CBC)
		return cipher.decrypt(data)

	def aes128_kw(self, data, key):
		from Crypto.Cipher import AES
		cipher = AES.new(key, AES.mode)

	@classmethod
	def idpf_obfuscation(self, fp, key):
		from hashlib import sha1
		enc_key = sha1(bytes(re.sub(r'\s', '', key), 'utf-8')).digest()
		outer = 0
		while outer < 52:
			inner = 0
			while inner < 20:
				sourceByte = fp.read(1)
				if not sourceByte: break
				keyByte = enc_key[inner]
				yield (sourceByte[0] ^ keyByte).to_bytes(1, 'big')
				inner += 1
			outer += 1


if __name__ == '__main__':
	from zipfile import ZipFile
	from io import BytesIO
	from hashlib import sha1
	key = 'code.google.com.epub-samples.wasteland-otf-obfuscated'
	print(chr(9))
	# z = ZipFile('wasteland-otf-obf.epub', 'r')
	# out = open('OldStandard-Regular.otf', 'wb')
	# in_ = BytesIO()
	# in_.write(z.read('EPUB/OldStandard-Bold.obf.otf'))
	# with z.open('EPUB/OldStandard-Regular.obf.otf') as in_:
	# in_.seek(0)
	# out = open('OldStandard-Bold.otf', 'wb')
	# with open('OldStandard-Bold.otf', 'rb') as in_:
	# 	b = in_.read(4)
	# 	print(b)

	# 	for b in epubContainer.idpf_obfuscation(in_, key):
	# 		out.write(b)
	# 	out.write(in_.read())
	# 	out.close()
	# z.close()

