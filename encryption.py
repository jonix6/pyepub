
import re
from hashlib import sha1, md5

from Crypto import Random
from Crypto.Cipher import DES3
from Crypto.Cipher import AES

class default_cipher:
	URI = ''
	def __init__(self, key):
		self.key = key

	def encrypt(self, data):
		return data

	def decrypt(self, data):
		return data

class idpf_obfuscation(default_cipher):
	URI = 'http://www.idpf.org/2008/embedding'
	def obfuscate(self, data):
		enc_key = sha1(bytes(re.sub(r'\s', '', self.key), 'utf-8')).digest()

		chunk = data[:1040]
		outer = 0
		obfuscated = bytearray()
		while outer < 52:
			inner = 0
			while inner < 20:
				index = outer*20+inner
				if index >= len(chunk): break
				sourceByte = chunk[index]
				keyByte = enc_key[inner]
				obfuscated.append(sourceByte ^ keyByte)
				inner += 1
			outer += 1
		return obfuscated+data[1040:]

	encrypt = lambda self, data: self.obfuscate(data)
	decrypt = lambda self, data: self.obfuscate(data)

class des3(default_cipher):
	URI = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
	cipher = DES3
	size = DES3.block_size
	def __init__(self, key, iv):
		self.key = key
		self.iv = iv

	def pad(self, data, n, nbit=0x20):
		x = (n - len(data) % n) % n
		return data + nbit.to_bytes(1, 'big')*x, x

	def unpad(self, data):
		if not x: return data
		return data[:-x]

	def encrypt(self, data):
		key, x = self.pad(self.key[:self.size*2], self.size*2)
		data, _ = self.pad(data, self.size, nbit=x)
		iv, _ = self.pad(self.iv[:self.size], self.size)
		return self.cipher.new(key, mode=self.cipher.MODE_CBC, IV=iv).encrypt(data)

	def decrypt(self, data):
		key, x = self.pad(self.key[:self.size*2], self.size*2)
		iv, _ = self.pad(self.iv[:self.size], self.size)
		nbit = x.to_bytes(1, 'big')
		return self.cipher.new(key, mode=self.cipher.MODE_CBC, IV=iv).decrypt(data).rstrip(nbit)

class aes128(des3):
	URI = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
	cipher = AES
	size = 16
	def encrypt(self, data):
		key, x = self.pad(self.key[:self.size], self.size)
		data, _ = self.pad(data, self.size, nbit=x)
		iv, _ = self.pad(self.iv[:self.size], self.size)
		return self.cipher.new(key, mode=self.cipher.MODE_CBC, IV=iv).encrypt(data)

	def decrypt(self, data):
		key, x = self.pad(self.key[:self.size], self.size)
		iv, _ = self.pad(self.iv[:self.size], self.size)
		nbit = x.to_bytes(1, 'big')
		return self.cipher.new(key, mode=self.cipher.MODE_CBC, IV=iv).decrypt(data).rstrip(nbit)

class aes192(aes128):
	URI = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc'
	size = 24
class aes256(aes128):
	URI = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
	size = 32

class des3_kw(des3):
	URI = 'http://www.w3.org/2001/04/xmlenc#kw-tripledes'
	def __init__(self, key):
		des3.__init__(self, key)
		self.iv = bytearray([0x4a,0xdd,0xa2,0x2c,0x79,0xe8,0x21,0x05])

	def key_wrap(self):
		key = (self.key + bytearray(16))[:16]
		wkcks = self.key
		wkcks += sha1(self.key).digest()[:DES3.block_size]
		iv = Random.new().read(DES3.block_size)
		temp1 = DES3.new(key, mode=DES3.MODE_CBC, IV=iv).encrypt(wkcks)
		temp2 = (iv + temp1)[::-1]
		return DES3.new(self.key, mode=DES3.MODE_CBC, IV=self.iv).encrypt(temp2)

	def encrypt(self, data):
		key = self.key_wrap()
		return DES3.DES3Cipher(key, DES3.MODE_ECB).encrypt(data)
	def decrypt(self, data):
		key = self.key_unwrap()
		return DES3.DES3Cipher(key, DES3.MODE_ECB).decrypt(data)


if __name__ == '__main__':
	pwd = b'haha'
	content = b'i love you123456'
	iv = Random.new().read(16)
	cipher = aes192(pwd, iv)
	dcontent = cipher.encrypt(content)
	print(dcontent)
	cipher2 = aes192(pwd, iv)
	print(cipher.decrypt(dcontent))
	# uid = 'code.google.com.epub-samples.wasteland-otf-obfuscated'
	# cipher = idpf_obfuscation(uid)
	# with open('OldStandard-Regular.obf.otf', 'rb') as fp:
	# 	with open('OldStandard-Regular.otf', 'wb') as ofp:
	# 		ofp.write( cipher.encrypt(fp.read()) )
