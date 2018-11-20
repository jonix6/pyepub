#coding: utf-8
import hashlib
import os
import re
from collections import namedtuple

MIMETYPE = b'application/epub+zip'

def _vertuple(versions):
	verdict = dict( map(lambda x: ('v'+x.replace('.','_'), x), versions) )
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

def isbn10_validate(isbn10:str, fix:bool=False):
	isbn = re.sub(r'[^\dx]', '', isbn10.lower())
	if not len(isbn) == 10:
		return False, isbn, ''
	checksum = (11 - sum(map(lambda x,y: int(x)*y, isbn[:-1], range(10,1,-1))) % 11) % 11
	checksum = str(checksum) if checksum < 10 else 'x'
	valid = checksum == isbn[-1].lower()
	if not fix:
		return valid, isbn, ''
	isbn13 ='978' + isbn[:-1]
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

def realpath(path:str, basepath:str, sep:str='/'):
	basedir = basepath if os.path.isdir(basepath) else os.path.dirname(basepath)
	return os.path.normpath(os.path.join(basedir, path)).replace('\\', sep)

def refpath(path:str, basepath:str, sep:str='/'):
	basedir = basepath if os.path.isdir(basepath) else os.path.dirname(basepath)
	return os.path.relpath(path, basedir).replace('\\', sep)

def filename(filepath:str):
	return os.path.splitext(os.path.basename(filepath).lower())

if __name__ == '__main__':
	print(os.path.basename('s04.xhtml#pgepubid00492'))
	print(realpath('s04.xhtml#pgepubid00492', 'EPUB/nav.xhtml'))

