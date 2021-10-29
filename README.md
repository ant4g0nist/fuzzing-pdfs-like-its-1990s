# Fuzzing PDFs like its 1990s
This is the fuzzer I made to fuzz Preview on macOS and iOS like 8years back when I just started fuzzing things.

Some disclosed vulnerabilities:
- CVE-2015-3723
- CVE-2016-1737
- CVE-2016-1740
- CVE-2017-7031

# Info
The basic idea of this fuzzer was to mutate the streams of the pdf files without screwing the PDF Structure as a whole. I collected some hundreds of PDFs and converted the PDFs to Python script using Didier Stevens's [pdf-parser](https://blog.didierstevens.com/programs/pdf-tools/) -g flag. The fuzzer uses `cPDF` that I modified to mutate the stream using Charlie's 10liner, every time I try to generate a PDF file.

This made it really easy to mutate the stream and create the PDF file from the fuzzing server.

I used Charlie's 10liner for mutations:
```
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
```

# Usage
Meh! it's a python script, use it as you wish!

- More power, more bugs??