def func_7d3336e117d34ab5ab540b6cfaef8e99(cPDF):
    oPDF = cPDF()
    oPDF.header('1.7')
    oPDF.indirectobject(1, 0, '<<\r\n \t/Type /Catalog\r\n  \t/Pages 2 0 R\r\n>>')
    oPDF.indirectobject(2, 0, '<<\r\n  \t/Type /Pages\r\n  \t/Kids [3 0 R]\r\n  \t/Count 1\r\n>>')
    oPDF.indirectobject(3, 0, '% Page object\r\n<<\r\n  \t/Type /Page\r\n  \t/Parent 2 0 R\r\n \t/Resources 4 0 R\r\n  \t/Contents 30 0 R\r\n\t/MediaBox [0 0 600 600]\r\n  \t%/CropBox [0 0 400 300]\r\n>>')
    oPDF.indirectobject(4, 0, '<<\r\n  /Shading <</Sh2 6 0 R>>\r\n  /Pattern <</P1 10 0 R>>\r\n>>')
    oPDF.indirectobject(6, 0, '%See page 305 and page 308\r\n<<\r\n  /ShadingType 1\t\t%Function-based shading\r\n  /ColorSpace /DeviceRGB\r\n  /Domain [-1.0 1.0 -1.0 1.0]\r\n  /Function [9 0 R 9 0 R 9 0 R] %ÕâÀïËµÃ÷RGBÈý¸ö·ÖÁ¿µÄÖµÊÇÒ»ÑùµÄ£¬Ò²¾ÍÊÇËµÕâÓ¦¸ÃÊÇÒ»¸ö´Ó°×µ½ºÚÖ®¼äµÄÑÕÉ«\r\n\r\n  /Matrix [72 0 0 72 0 0]\t%1 inch\r\n% /BBox [0 0 72 72]\r\n /BBox [0 0 100 100] \r\n /Background [0.0 0.5 0.1]\r\n>>')
    oPDF.stream(9, 0, '{\r\n360 mul sin  2 div  exch 360 mul sin  2 div  add\r\n}', '<<\r\n  /FunctionType 4\r\n  /Domain  [-1.0 1.0 -1.0 1.0 ]\r\n% /Domain  [0 2.0 0.0 2.0 ]\r\n  /Range  [-1.0 1.0]\r\n  /Length %d\r\n>>')
    oPDF.indirectobject(10, 0, '<<\r\n\t/Type /Pattern\r\n\t/PatternType 2\r\n\t/Shading 6 0 R\r\n>>')
    oPDF.stream(30, 0, '\r\n\r\n\r\nq\r\n/Pattern cs\r\n/P1 scn\r\n0 0 300 300 re\r\nf\r\nQ', '<<\r\n  /Length %d\r\n>>')
    oPDF.xrefAndTrailer('1 0 R')
    return oPDF.sample()
