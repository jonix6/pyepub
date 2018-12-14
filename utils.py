#coding: utf-8
import hashlib
import os
import re
from collections import namedtuple
from urllib.parse import urlparse, urlunparse, quote, unquote

MIMETYPE = b'application/epub+zip'

def _vertuple(versions):
	verdict = dict(map(lambda x: ('v'+x.replace('.','_'), x), versions))
	version = namedtuple('version', list(verdict))
	return version(**verdict)
version2 = _vertuple(['2.0', '2.0.1'])
version3 = _vertuple(['3.0', '3.0.1', '3.1', '3.2'])

mimetypes = {
	'.css': 'text/css',
	'.xhtml': 'application/xhtml+xml',
	'.html': 'application/xhtml+xml',
	'.jpg': 'image/jpeg',
	'.jpeg': 'image/jpeg',
	'.png': 'image/png',
	'.gif': 'image/gif',
	'.svg': 'image/svg+xml',
	'.ttf': 'application/font-sfnt',
	'.otf': 'application/font-sfnt',
	'.woff': 'application/font-woff',
	'.woff2': 'font/woff2',
	'.js': 'application/javascript',
	'.mp3': 'audio/mpeg',
	'.mp4': 'audio/mp4',
	'.smil': 'application/smil+xml',
	'.pls': 'application/pls+xml',
	'.ncx': 'application/x-dtbncx+xml',
	'.opf': 'application/oebps-package+xml'
}

_restypes = {
	'document': ['.xhtml', '.html'],
	'image': ['.jpg', '.jpeg', '.png', '.gif', '.svg'],
	'stylesheet': ['.css'],
	'font': ['.ttf', '.otf', '.woff', '.woff2'],
	'audio': ['.mp3', '.mp4'],
	'script': ['.js']
}
restypes = {}
for restype, exts in _restypes.items():
	for ext in exts:
		restypes[mimetypes[ext]] = restype

marc_codes = {
	'adp': ('adapter', '改编者'),
	'ann': ('annotator', '注解者'),
	'arr': ('arranger', '编曲'),
	'art': ('artist', '艺术家'),
	'asn': ('associated name', '相关人员'),
	'aut': ('author', '作者'),
	'aqt': ('author in quotations or text extracts', '引文作者'),
	'aft': ('author of afterword', '文后作者'),
	'aui': ('author of introduction', '文前作者'),
	'ant': ('bibliographic antecedent', '书目履历'),
	'bkd': ('book designer', '图书设计'),
	'bkp': ('book producer', '制书人'),
	'clb': ('collaborator', '合作作者'),
	'cmm': ('commentator', '评论员'),
	'com': ('compiler', '编者'),
	'crr': ('corrector', '校正'),
	'ctg': ('cartographer', '制图'),
	'dsr': ('designer', '设计者'),
	'edt': ('editor', '编辑'),
	'ill': ('illustrator', '插图作者'),
	'lyr': ('lyricist', '作词'),
	'mdc': ('metadata contact', '元数据维护者'),
	'mus': ('musician', '作曲'),
	'nrt': ('narrator', '叙述者'),
	'oth': ('other', '其他'),
	'pbl': ('publisher', '出版'),
	'pfr': ('proofreader', '校对'),
	'pht': ('photographer', '摄影'),
	'prt': ('printer', '印刷'),
	'red': ('redactor', '主编'),
	'rev': ('reviewer', '评论家'),
	'spn': ('sponsor', '赞助'),
	'ths': ('thesis advisor', '论文指导'),
	'trc': ('transcriber', '抄录'),
	'trl': ('translater', '翻译者'),
	'tyd': ('type designer', '字体设计')
}

def isbn10_validate(isbn10:str, fix:bool=False):
	isbn = re.sub(r'[^\dx]', '', isbn10.lower())
	if not len(isbn) == 10:
		return False, isbn, ''
	checksum = (11 - sum(map(lambda x,y: int(x)*y, isbn[:-1], range(10,1,-1))) % 11) % 11
	checksum = str(checksum) if checksum < 10 else 'x'
	valid = checksum == isbn[-1].lower()
	if not fix:
		return valid, isbn, ''
	isbn13 = '978' + isbn[:-1]
	checksum = (10 - sum(map(lambda x,y: int(x)*y, isbn13, [1,3]*6)) % 10) % 10
	return valid, isbn, isbn13+str(checksum)

def isbn_validate(isbn:str, fix:bool=False):
	isbn = re.sub(r'[^\dx]', '', isbn.lower())
	if not len(isbn) == 13:
		if len(isbn) == 10 and fix:
			return isbn10_validate(isbn, fix=True)
		return False, isbn, ''
	checksum = (10 - sum(map(lambda x,y: int(x)*y, isbn[:-1], [1,3]*6)) % 10) % 10
	valid = str(checksum) == isbn[-1]
	if not fix:
		return valid, isbn, ''
	return valid, isbn, isbn[:-1]+str(checksum)

def md5hash(fp, chunksize:int=1<<10):
	filehash = hashlib.md5()
	if isinstance(fp, str):
		fp = open(fp, 'rb')
	pos = fp.tell()
	fp.seek(0)
	while True:
		chunk = fp.read(chunksize)
		if not chunk:
			break
		filehash.update(chunk)
	fp.seek(pos)
	return fp, filehash.hexdigest()

def realpath(url:str, baseurl:str, encode_in=True, encode_out=False):
	if encode_in:
		url = unquote(url)
	urlp = urlparse(url)
	baseurlp = urlparse(baseurl)
	if urlp.scheme:
		return urlunparse(urlp)
	urlp = urlp._replace(scheme=baseurlp.scheme)
	if urlp.netloc:
		return urlunparse(urlp)
	if urlp.path:
		basedir = baseurlp.path
		if not os.path.isdir(basedir):
			basedir = os.path.dirname(basedir)
		path = os.path.normpath(os.path.join(basedir, urlp.path)).replace('\\', '/')
	else:
		path = baseurlp.path
	if encode_out:
		path = quote(path)
	urlp = urlp._replace(netloc=baseurlp.netloc, path=path)
	return urlunparse(urlp)

def refpath(url:str, baseurl:str):
	urlp = urlparse(url)
	baseurlp = urlparse(baseurl)
	if urlp.scheme != baseurlp.scheme:
		return urlunparse(urlp)
	urlp = urlp._replace(scheme='')
	if urlp.netloc != baseurlp.netloc:
		return urlunparse(urlp)
	urlp = urlp._replace(netloc='')
	path = urlp.path or '/'
	basedir = baseurlp.path or '/'
	if not os.path.isdir(basedir):
		basedir = os.path.dirname(basedir)
	path = os.path.relpath(path, basedir).replace('\\', '/')
	urlp = urlp._replace(path=path)
	return urlunparse(urlp)

def filename(filepath:str):
	return os.path.splitext(os.path.basename(filepath).lower())

def keygen(key_type='rsa', bits=2048, format='PEM', pkcs8=False):
	from Crypto.PublicKey import DSA, RSA, ECC
	key_generator = {
		'rsa': lambda: RSA.generate(bits),
		'dsa': lambda: DSA.generate(bits),
		'ecdsa': lambda: ECC.generate(curve='P-256')
	}
	privatekey_generator = {
		'rsa': lambda key: key.export_key(format=format, pkcs=[8,1][int(pkcs8)-1]),
		'dsa': lambda key: key.export_key(format=format, pkcs8=pkcs8),
		'ecdsa': lambda key: key.export_key(format=format, use_pkcs8=pkcs8)
	}
	pubkey_generator = {
		'rsa': lambda key: key.publickey().export_key(format=format),
		'dsa': lambda key: key.publickey().export_key(format=format),
		'ecdsa': lambda key: key.public_key().export_key(format=format)
	}
	key = key_generator[key_type]()
	privatekey = privatekey_generator[key_type](key)
	pubkey = pubkey_generator[key_type](key)
	return pubkey, privatekey

if __name__ == '__main__':
	print(realpath('../%E5%93%88%E5%93%88s04.xhtml#pgepubid00492', 'EPUB/nav.xhtml'))
	print(refpath('https://static.bshare.cn/b/buttonLite.js#style=-1&uuid=&pophcol=2&lang=zh', 
		'https://static.bshare.cn'))

