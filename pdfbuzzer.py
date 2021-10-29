
#!/usr/bin/python
import os
import sys
import glob
import math
import zlib
import random
import platform

path = "./pys/"
funcs = glob.glob(path+"/*.py")

sys.path.append(path)
pdfs = {}

for i in funcs:
	if "__init__" not in i:
		name = os.path.basename(i)[:-3]
		try:
			func = __import__(name)
			pdfs[name] = func
		except:
			pass

fuzzFactor = 30
def bitman_(buf):
	buf = bytearray(buf.encode())
	try:
		numwrites = random.randrange(math.ceil((float(len(buf))/fuzzFactor))) + 1
	except:
		numwrites=10

	for j in range(numwrites):
		rbyte = random.randrange(256)
		rn = random.randrange(len(buf))
		buf[rn] = rbyte
	return str(buf)

def SplitByLength(input, length):
	result = []
	while len(input) > length:
		result.append(input[0:length] + '\n')
		input = input[length:]
	result.append(input + '>')
	return result

class cPDF:
	def __init__(self):
		self.indirectObjects = {}

	def appendString(self, stri):
		self.output+=stri

	def comment(self, stri):
		pass

	def appendBinary(self, stri):
		self.output+=stri

	def filesize(self):
		size = len(self.output)
		return size

	def IsWindows(self):
		return platform.system() in ('Windows', 'Microsoft')

	def header(self,version):
		self.output=f'%PDF-{version}\n'

	def binary(self):
		self.appendString("%\xD0\xD0\xD0\xD0\n")

	def indirectobject(self, index, version, io):
		self.appendString("\n")
		self.indirectObjects[index] = self.filesize()
		self.appendString("%d %d obj\n%s\nendobj\n" % (index, version, io))

	def stream(self, index, version, streamdata, dictionary="<< /Length %d >>"):
		#this can be used for fuzzing
		self.appendString("\n")

		self.indirectObjects[index] = self.filesize()

		#bit manupulation of stream data
		try:
		    streamdata_=bitman_(streamdata)
		except Exception as e:
		    print(e)
		    streamdata_=streamdata

		self.appendString(("%d %d obj\n<< /Length %d >>\nstream\n") % (index, version, len(streamdata_)))
		self.appendBinary(streamdata_)
		self.appendString("\nendstream\nendobj\n")

	def Data2HexStr(self, data):
		hex = ''
		if sys.version_info[0] == 2:
			for b in data:
				hex += "%02x" % ord(b)
		else:
			for b in data:
				hex += "%02x" % b
		return hex

	def stream2(self, index, version, streamdata, entries="", filters=""):
		"""
	* h ASCIIHexDecode
	* H AHx
	* i like ASCIIHexDecode but with 512 long lines
	* I like AHx but with 512 long lines
	* ASCII85Decode
	* LZWDecode
	* f FlateDecode
	* F Fl
	* RunLengthDecode
	* CCITTFaxDecode
	* JBIG2Decode
	* DCTDecode
	* JPXDecode
	* Crypt
		"""

		encodeddata = streamdata
		#bit manupulation of stream data
		try:
			encodeddata=bitman_(bytearray(encodeddata))
		except:
			encodeddata=encodeddata

		filter = []
		for i in filters:
			if i.lower() == "h":
				encodeddata = self.Data2HexStr(encodeddata) + '>'
				if i == "h":
					filter.insert(0, "/ASCIIHexDecode")
				else:
					filter.insert(0, "/AHx")
			elif i.lower() == "i":
				encodeddata = ''.join(SplitByLength(self.Data2HexStr(encodeddata), 512))
				if i == "i":
					filter.insert(0, "/ASCIIHexDecode")
				else:
					filter.insert(0, "/AHx")
			elif i.lower() == "f":
				encodeddata = zlib.compress(encodeddata)
				if i == "f":
					filter.insert(0, "/FlateDecode")
				else:
					filter.insert(0, "/Fl")
			else:
				print("Error")
				return
		self.appendString("\n")
		self.indirectObjects[index] = self.filesize()
		self.appendString("%d %d obj\n<<\n /Length %d\n" % (index, version, len(encodeddata)))
		if len(filter) == 1:
			self.appendString(" /Filter %s\n" % filter[0])
		if len(filter) > 1:
			self.appendString(" /Filter [%s]\n" % ' '.join(filter))
		if entries != "":
			self.appendString(" %s\n" % entries)
		self.appendString(">>\nstream\n")
		if filters[-1].lower() == 'i':
			self.appendString(encodeddata)
		else:
			self.appendBinary(encodeddata)
		self.appendString("\nendstream\nendobj\n")

	def xref(self):
		self.appendString("\n")
		startxref = self.filesize()
		max = 0
		for i in self.indirectObjects.keys():
			if i > max:
				max = i
		self.appendString("xref\n0 %d\n" % (max+1))
		if self.IsWindows():
			eol = '\n'
		else:
			eol = ' \n'
		for i in range(0, max+1):
			if i in self.indirectObjects:
				self.appendString("%010d %05d n%s" % (self.indirectObjects[i], 0, eol))
			else:
				self.appendString("0000000000 65535 f%s" % eol)
		return (startxref, (max+1))

	def trailer(self, startxref, size, root, info=None):
		if info == None:
			self.appendString("trailer\n<<\n /Size %d\n /Root %s\n>>\nstartxref\n%d\n%%%%EOF\n" % (size, root, startxref))
		else:
			self.appendString("trailer\n<<\n /Size %d\n /Root %s\n /Info %s\n>>\nstartxref\n%d\n%%%%EOF\n" % (size, root, info, startxref))

	def xrefAndTrailer(self, root, info=None):
		xrefdata = self.xref()
		self.trailer(xrefdata[0], xrefdata[1], root, info)

	def template1(self):
		self.indirectobject(1, 0, "<<\n /Type /Catalog\n /Outlines 2 0 R\n /Pages 3 0 R\n>>")
		self.indirectobject(2, 0, "<<\n /Type /Outlines\n /Count 0\n>>")
		self.indirectobject(3, 0, "<<\n /Type /Pages\n /Kids [4 0 R]\n /Count 1\n>>")
		self.indirectobject(4, 0, "<<\n /Type /Page\n /Parent 3 0 R\n /MediaBox [0 0 612 792]\n /Contents 5 0 R\n /Resources <<\n             /ProcSet [/PDF /Text]\n             /Font << /F1 6 0 R >>\n            >>\n>>")
		self.indirectobject(6, 0, "<<\n /Type /Font\n /Subtype /Type1\n /Name /F1\n /BaseFont /Helvetica\n /Encoding /MacRomanEncoding\n>>")

	def sample(self):
		return self.output

funcs = list(pdfs.keys())

def fuzz():
	func = pdfs[random.choice(funcs)]
	poc = eval(f"func.func_{func.__name__}(cPDF)")
	return poc

for i in range(0, len(funcs)):
	func = pdfs[funcs[i]]
	
	poc = eval(f"func.func_{func.__name__}(cPDF)")
	if not poc:
		print(f"func.func_{func.__name__}(cPDF)")
	else:
		with open(f"/Users/ant4g0nist/Downloads/test/{i}.pdf", 'w') as f:
			f.write(poc)