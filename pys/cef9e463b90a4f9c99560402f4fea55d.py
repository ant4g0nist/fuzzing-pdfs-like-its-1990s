def func_cef9e463b90a4f9c99560402f4fea55d(cPDF):
    oPDF = cPDF()
    oPDF.header('1.4')
    oPDF.indirectobject(1, 0, '<<\r\n/Type /Catalog\r\n/Pages 2 0 R\r\n/AcroForm 3 0 R\r\n>>')
    oPDF.indirectobject(2, 0, '<<\r\n/Type /Pages\r\n/Kids [4 0 R 41 0 R]\r\n/Count 2\r\n>>')
    oPDF.indirectobject(3, 0, '<<\r\n/Fields [6 0 R]\r\n>>')
    oPDF.indirectobject(4, 0, '<<\r\n/Type /Page\r\n/Parent 2 0 R\r\n/MediaBox [0 0 500 600]\r\n/Contents 5 0 R\r\n/Annots [9 0 R]\r\n>>')
    oPDF.indirectobject(41, 0, '<<\r\n/Type /Page\r\n/Parent 2 0 R\r\n/MediaBox [0 0 500 600]\r\n/Contents 5 0 R\r\n\r\n>>')
    oPDF.stream(5, 0, '\r\n1 0 0 RG\r\n50 50 400 500 re S', '<<\r\n/Length %d\r\n>>')
    oPDF.indirectobject(6, 0, '<<\r\n/Parent 3 0 R\r\n/T (Button)\r\n/Kids [9 0 R]\r\n>>')
    oPDF.indirectobject(9, 0, '<<\r\n/Type /Annot\r\n/Subtype /Link\r\n/Parent 6 0 R\r\n/Rect [150 150 250 250]\r\n/Border [16 16 1]\r\n/A << /Type /Action\r\n      /S /GoTo\r\n      /D [41 0 R  /Fit]\r\n   >>\r\n>>')
    oPDF.xrefAndTrailer('1 0 R')
    return oPDF.sample()