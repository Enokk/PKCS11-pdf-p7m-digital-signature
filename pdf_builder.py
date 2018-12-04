import pdf_signer
from io import BytesIO
from zlib import compress
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfparser import PDFParser
from datetime import datetime, timezone
from PyKCS11 import Mechanism, LowLevel
from asn1crypto.x509 import Certificate

from my_config_loader import MyConfigLoader
from my_logger import MyLogger

FRM_STREAM = b'q 1 0 0 1 0 0 cm /FRM Do Q\n'
N0_N2_STREAM = b'q 1 0 0 1 0 0 cm /n0 Do Q\nq 1 0 0 1 0 0 cm /n2 Do Q\n'
DSBLANK_STREAM = b'% DSBlank\n'
STREAM_WITH_NAME = b'BT\n1 0 0 1 2 28 Tm\n/F1 12 Tf\n()Tj\n1 0 0 1 2 16 Tm\n(%s)Tj\nET\n'
sig_names = {}


# Custom exceptions:
class PDFCreationError(Exception):
    ''' Raised when failing to create pdf '''
    pass


class PDFSigningError(Exception):
    ''' Raised when failing to sign pdf '''
    pass


class Signature:
    def __init__(self, name, pos):
        self.name = name
        self.pos = pos


class SignedData(object):

    def aligned(self, data):
        data = data.hex().encode('utf-8')
        csize = (0x5000 / 2) * 2
        nb = csize - len(data)
        data = data + b'0' * (int(csize) - len(data))
        return data

    def getdata(self, pdfdata1, objid, startxref, document):
        i0 = None
        for xref in document.xrefs:
            try:
                (strmid, index, genno) = xref.get_pos(objid)
            except KeyError:
                continue
            i0 = index
            break
        i1 = startxref
        for xref in document.xrefs:
            for (_, offset, _) in xref.offsets.values():
                if offset > i0:
                    i1 = min(i1, offset)
        if i1 <= i0:
            data = pdfdata1[i0:len(pdfdata1)]
            i0 = data.find(b'<<') + 2
            i1 = data.find(b'>>\rendobj')
        else:
            data = pdfdata1[i0:i1]
            i0 = data.find(b'<<') + 2
            i1 = data.rfind(b'>>')

        data = data[i0:i1]
        return data

    def get_timestamp(self):
        utc_dt = datetime.now(timezone.utc)  # UTC time
        dt = utc_dt.astimezone().strftime("%Y%m%d%H%M%S%z")
        time_stamp = str(dt)
        return time_stamp[:-2] + '\'' + time_stamp[-2:] + '\''

    def get_sig_names(self):
        return sig_names

    def get_signature_names(self, document):
        sorter = []
        try:
            acrofields = document.catalog['AcroForm']['Fields']
        except:
            pass
        try:
            acroform_objid = document.catalog['AcroForm'].objid
            acrofields = document.getobj(acroform_objid)['Fields']
        except:
            print('Non sono presenti firme sul documento')
            return []
        for field in acrofields:
            field_obj = document.getobj(field.objid)
            if field_obj['FT'].name == 'Sig':
                if field_obj['V']:
                    signed_field = document.getobj(field_obj['V'].objid)
                    if signed_field['Contents']:
                        byte_range = signed_field['ByteRange']
                        if byte_range:
                            b_size = byte_range.__len__()
                            if b_size >= 2:
                                length = byte_range[b_size - 1] + byte_range[b_size - 2]
                                sorter.append(Signature(field_obj['T'].decode(), [length, 0]))
                                #  sorter.append(Signature('signature1', [length*3, 0]))  # test purpose
                                #  sorter.append(Signature('signature2', [length*2, 0]))  # test purpose
        if sorter.__len__() != 0:
            sorter.sort(key=lambda x: x.pos[0])
        for key, item in enumerate(sorter):
            p = item.pos
            p[1] = key + 1
            sig_names[item.name] = p

        return sig_names

    def get_rect_array(self, pagedata, position):
        mbx = pagedata.find(b'MediaBox') + len('MediaBox') + 1
        mby = pagedata[mbx:len(pagedata)].find(b']')
        mediabox = pagedata[mbx:mbx + mby].decode().split(' ')
        llx = float(mediabox[2]) - position['width'] - position['padding_width']
        lly = float(mediabox[3]) - position['height'] - position['padding_height']
        urx = llx + position['width']
        ury = lly + position['height']
        return [llx, lly, urx, ury]

    def get_annots_fields_values(self, document):
        try:
            acrofields = document.catalog['AcroForm']['Fields']
        except:
            pass
        try:
            acroform_objid = document.catalog['AcroForm'].objid
            acrofields = document.getobj(acroform_objid)['Fields']
        except:
            raise PDFCreationError('Fields not found in AcroForm tag')
        fields_values = b''
        for field in acrofields:
            fields_values += b'%d 0 R ' % field.objid
        return fields_values

    def get_new_pagedata(self, pagedata):
        annot_start = pagedata.find(b'/Annots')
        annot_end = pagedata.find(b']/', annot_start)
        return pagedata[:annot_start + 8] + b'%s%d 0 R' + pagedata[annot_end:]

    def get_new_rootdata(self, rootdata):
        field_start = rootdata.find(b'/Fields')
        if field_start == -1:
            return rootdata
        field_end = rootdata.find(b']/', field_start)
        return rootdata[:field_start + 8] + b'%s%d 0 R' + rootdata[field_end:]

    def makeobj(self, no, data):
        return (b'%d 0 obj\n<<' % no) + data + b'>>\nendobj\n'

    def makeobj_stream(self, no, data, stream):
        return (b'%d 0 obj\n<<' % no) + data + b'>>stream\n' + stream + b'\nendstream\nendobj\n'

    # Contains the font stream encoded
    def makeobj_font_stream(self, no, data, stream):
        return (b'%d 0 obj\n<<' % no) + data + b'>>' + stream + b'\nendobj\n'

    def make_visible_sig_objs(self, udct, no, page, pagedata, infodata, rootdata, stream_name, rect, zeros):
        objs = [
            self.makeobj(page, (b'/Annots[%d 0 R]' % (no + 3)) + pagedata),
            self.makeobj(no + 0, infodata),
            self.makeobj(no + 1, (b'/AcroForm %d 0 R' % (no + 2)) + rootdata),
            self.makeobj(no + 2, b'/Fields[%d 0 R]/SigFlags %d/DA(/Helv 0 Tf 0 g)/DR <</Font<</ZaDb %d 0 R/Helv %d 0 R>>>>' % (no + 3, udct[b'sigflags'], no + 12, no + 13)),
            self.makeobj(no + 3,
                    b'/AP<</N %d 0 R>>/Type/Annot/F 132/DA(/Arial 0 Tf 0 g)/FT/Sig/DR <<>>/P %d 0 R/Rect[%.2f %.2f %.2f %.2f]/Subtype/Widget/T(null)/V %d 0 R' % (no + 4, page, rect[0], rect[1], rect[2], rect[3], no + 5)),
            self.makeobj_stream(no + 4, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]/XObject<</FRM %d 0 R>>>>/BBox[0 0 200 60]/Length 29' % (no + 6), compress(FRM_STREAM)),
            b'stream\n\x78\x9C\x03\x00\x00\x00\x00\x01\nendstream\n',
            self.makeobj(no + 5,
                 (b'/ByteRange [0000000000 0000000000 0000000000 0000000000]/Name(%s)/Filter/Adobe.PPKLite/M(D:%s)/SubFilter/ETSI.CAdES.detached/Type/Sig/FT/Sig/Contents <' % (udct[b'name'], udct[b'signingdate'])) + zeros + b'>'),
            self.makeobj_stream(no + 6, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]/XObject<</n0 %d 0 R/n2 %d 0 R>>>>/BBox[0 0 200 60]/Length 34' % (no + 7, no + 8), compress(N0_N2_STREAM)),
            self.makeobj_stream(no + 7, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]>>/BBox[0 0 100 100]/Length 18', compress(DSBLANK_STREAM)),
            self.makeobj_stream(no + 8, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]/Font<</F1 %d 0 R>>>>/BBox[0 0 200 60]/Length %d' % (no + 9, len(stream_name)), stream_name),
            self.makeobj(no + 9, b'/Subtype/TrueType/FirstChar 32/Type/Font/BaseFont/ArialMT/FontDescriptor %d 0 R/Encoding/WinAnsiEncoding/LastChar 126/Widths[277 277 354 556 556 889 666 190 333 333 389 583 277 333 277 277 556 556 556 556 556 556 556 556 556 556 277 277 583 583 583 556 1015 666 666 722 722 666 610 777 722 277 500 666 556 833 722 777 666 777 722 666 610 722 666 943 666 666 610 277 277 277 469 556 333 556 556 500 556 556 277 556 556 222 222 500 222 833 556 556 556 556 333 500 277 556 500 722 500 500 500 333 259 333 583]' % (no + 10)),
            self.makeobj(no + 10, b'/Descent -210/CapHeight 716/StemV 80/Type/FontDescriptor/FontFile2 %d 0 R/Flags 32/FontBBox[-664 -324 2000 1039]/FontName/ArialMT/ItalicAngle 0/Ascent 728' % (no + 11)),
            self.makeobj_font_stream(no + 11, b'/Length1 96488/Filter/FlateDecode/Length 44982', open('encoded_font.bin', 'rb').read().decode('unicode-escape').encode('ISO-8859-1')),
            self.makeobj(no + 12, b'/Name/ZaDb/Subtype/Type1/Type/Font/BaseFont/ZapfDingbats'),
            self.makeobj(no + 13, b'/Name/Helv/Subtype/Type1/Type/Font/BaseFont/Helvetica/Encoding/WinAnsiEncoding'),
        ]
        return objs

    def make_multi_visible_sig_objs(self, document, udct, no, page, pagedata, infodata, rootdata, stream_name, rect, zeros):
        fields_values = self.get_annots_fields_values(document)
        new_pagedata = self.get_new_pagedata(pagedata)
        new_rootdata = self.get_new_rootdata(rootdata)
        objs = [
            self.makeobj(page, new_pagedata % (fields_values, no + 2)),
            self.makeobj(no + 0, infodata),
        ]
        if rootdata != new_rootdata:
            objs.append(self.makeobj(no + 1, new_rootdata % (fields_values, no + 2)),)
        else:
            objs.append(self.makeobj(no + 1, new_rootdata),)
        objs.extend([
            self.makeobj(no + 2,
                    b'/AP<</N %d 0 R>>/Type/Annot/F 132/DA(/Arial 0 Tf 0 g)/FT/Sig/DR <</XObject<</FRM %d 0 R>>>>/P %d 0 R/Rect[%.2f %.2f %.2f %.2f]/Subtype/Widget/T(Signature2)/V %d 0 R' % (no + 3, no + 5, page, rect[0], rect[1], rect[2], rect[3], no + 4)),
            self.makeobj_stream(no + 3, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]/XObject<</FRM %d 0 R>>>>/BBox[0 0 200 60]/Length 29' % (no + 5), compress(FRM_STREAM)),
            b'stream\n\x78\x9C\x03\x00\x00\x00\x00\x01\nendstream\n',
            self.makeobj(no + 4,
                 (b'/ByteRange [0000000000 0000000000 0000000000 0000000000]/Name(%s)/Filter/Adobe.PPKLite/M(D:%s)/SubFilter/ETSI.CAdES.detached/Type/Sig/FT/Sig/Contents <' % (udct[b'name'], udct[b'signingdate'])) + zeros + b'>'),
            self.makeobj_stream(no + 5, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]/XObject<</n0 %d 0 R/n2 %d 0 R>>>>/BBox[0 0 200 60]/Length 34' % (no + 6, no + 7), compress(N0_N2_STREAM)),
            self.makeobj_stream(no + 6, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]>>/BBox[0 0 100 100]/Length 18', compress(DSBLANK_STREAM)),
            self.makeobj_stream(no + 7, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]/Font<</F1 %d 0 R>>>>/BBox[0 0 200 60]/Length %d' % (no + 8, len(stream_name)), stream_name),
            self.makeobj(no + 8, b'/Subtype/TrueType/FirstChar 32/Type/Font/BaseFont/ArialMT/FontDescriptor %d 0 R/Encoding/WinAnsiEncoding/LastChar 126/Widths[277 277 354 556 556 889 666 190 333 333 389 583 277 333 277 277 556 556 556 556 556 556 556 556 556 556 277 277 583 583 583 556 1015 666 666 722 722 666 610 777 722 277 500 666 556 833 722 777 666 777 722 666 610 722 666 943 666 666 610 277 277 277 469 556 333 556 556 500 556 556 277 556 556 222 222 500 222 833 556 556 556 556 333 500 277 556 500 722 500 500 500 333 259 333 583]' % (no + 9)),
            self.makeobj(no + 9, b'/Descent -210/CapHeight 716/StemV 80/Type/FontDescriptor/FontFile2 %d 0 R/Flags 32/FontBBox[-664 -324 2000 1039]/FontName/ArialMT/ItalicAngle 0/Ascent 728' % (no + 10)),
            self.makeobj_font_stream(no + 10, b'/Length1 96488/Filter/FlateDecode/Length 44982', open('encoded_font.bin', 'rb').read().decode('unicode-escape').encode('ISO-8859-1')),
        ])
        return objs

    def make_invisible_sig_objs(self, udct, no, page, pagedata, infodata, rootdata, zeros):
        objs = [
            self.makeobj(page, (b'/Annots[%d 0 R]' % (no + 3)) + pagedata),
            self.makeobj(no + 0, infodata),
            self.makeobj(no + 1, (b'/AcroForm %d 0 R' % (no + 2)) + rootdata),
            self.makeobj(no + 2, b'/Fields[%d 0 R]/SigFlags %d' % (no + 3, udct[b'sigflags'])),
            self.makeobj(no + 3, b'/AP<</N %d 0 R>>/Type/Annot/F 132/DA(/Arial 0 Tf 0 g)/FT/Sig/DR <<>>/P %d 0 R/Rect[0 0 0 0]/Subtype/Widget/T(null)/V %d 0 R' % (no + 4, page, no + 5)),
            self.makeobj_stream(no + 4, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]>>/BBox[0 0 0 0]/Length 8', compress(b'')),  # Lenght 8 per firma invisibile
            b'stream\n\x78\x9C\x03\x00\x00\x00\x00\x01\nendstream\n',
            self.makeobj(no + 5, (b'/Name(%s)/Filter/Adobe.PPKLite/Type/Sig/ByteRange [0000000000 0000000000 0000000000 0000000000]/SubFilter/ETSI.CAdES.detached/FT/Sig/M(D:%s)/Contents <' % (udct[b'name'], udct[b'signingdate'])) + zeros + b'>'),
        ]
        return objs

    def make_multi_inv_sig_objs(self, document, udct, no, page, pagedata, infodata, rootdata, zeros, sig_number):
        fields_values = self.get_annots_fields_values(document)
        new_pagedata = self.get_new_pagedata(pagedata)
        new_rootdata = self.get_new_rootdata(rootdata)
        objs = [
            self.makeobj(page, new_pagedata % (fields_values, no + 2)),
            self.makeobj(no + 0, infodata),
        ]
        if rootdata != new_rootdata:
            objs.append(self.makeobj(no + 1, new_rootdata % (fields_values, no + 2)),)
        else:
            objs.append(self.makeobj(no + 1, new_rootdata),)
        objs.extend([
            self.makeobj(no + 2, b'/AP<</N %d 0 R>>/Type/Annot/F 132/DA(/Arial 0 Tf 0 g)/FT/Sig/DR <<>>/P %d 0 R/Rect[0 0 0 0]/Subtype/Widget/T(Signature%d)/V %d 0 R' % (no + 3, page, sig_number, no + 4)),
            self.makeobj_stream(no + 3, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]>>/BBox[0 0 0 0]/Length 8', compress(b'')),  # Lenght 8 per firma invisibile
            b'stream\n\x78\x9C\x03\x00\x00\x00\x00\x01\nendstream\n',
            self.makeobj(no + 4, (b'/Name(%s)/Filter/Adobe.PPKLite/Type/Sig/ByteRange [0000000000 0000000000 0000000000 0000000000]/SubFilter/ETSI.CAdES.detached/FT/Sig/M(D:%s)/Contents <' % (udct[b'name'], udct[b'signingdate'])) + zeros + b'>'),
        ])
        return objs

    def make_visible_xref(self):
        return b'''\
xref\n\
%(page)d 1\n\
%(p0)010d 00000 n \n\
%(no)d 14\n\
%(n0)010d 00000 n \n\
%(n1)010d 00000 n \n\
%(n2)010d 00000 n \n\
%(n3)010d 00000 n \n\
%(n4)010d 00000 n \n\
%(n5)010d 00000 n \n\
%(n6)010d 00000 n \n\
%(n7)010d 00000 n \n\
%(n8)010d 00000 n \n\
%(n9)010d 00000 n \n\
%(n10)010d 00000 n \n\
%(n11)010d 00000 n \n\
%(n12)010d 00000 n \n\
%(n13)010d 00000 n \n\
'''

    def make_multi_visible_xref(self):
        return b'''\
xref\n\
%(page)d 1\n\
%(p0)010d 00000 n \n\
%(no)d 11\n\
%(n0)010d 00000 n \n\
%(n1)010d 00000 n \n\
%(n2)010d 00000 n \n\
%(n3)010d 00000 n \n\
%(n4)010d 00000 n \n\
%(n5)010d 00000 n \n\
%(n6)010d 00000 n \n\
%(n7)010d 00000 n \n\
%(n8)010d 00000 n \n\
%(n9)010d 00000 n \n\
%(n10)010d 00000 n \n\
'''

    def make_invisible_xref(self):
        return b'''\
xref\n\
%(page)d 1\n\
%(p0)010d 00000 n \n\
%(no)d 6\n\
%(n0)010d 00000 n \n\
%(n1)010d 00000 n \n\
%(n2)010d 00000 n \n\
%(n3)010d 00000 n \n\
%(n4)010d 00000 n \n\
%(n5)010d 00000 n \n\
'''

    def make_multi_inv_xref(self):
        return b'''\
xref\n\
%(page)d 1\n\
%(p0)010d 00000 n \n\
%(no)d 5\n\
%(n0)010d 00000 n \n\
%(n1)010d 00000 n \n\
%(n2)010d 00000 n \n\
%(n3)010d 00000 n \n\
%(n4)010d 00000 n \n\
'''

    def makepdf(self, pdfdata1, udct, zeros, sig_attributes):
        parser = PDFParser(BytesIO(pdfdata1))
        document = PDFDocument(parser, fallback=False)
        MyLogger().my_logger().info('get datas from pdf')
        prev = document.find_xref(parser)
        info = document.xrefs[0].trailer['Info'].objid
        root = document.xrefs[0].trailer['Root'].objid
        size = document.xrefs[0].trailer['Size']
        page_objid = document.catalog['Pages'].objid
        page = None

        MyLogger().my_logger().info('check attributes...')
        if not sig_attributes:
            visibility = MyConfigLoader().get_pdf_config()['visibility']
            position = MyConfigLoader().get_pdf_config()['position']
        else:
            visibility = sig_attributes['visibility']
            position = sig_attributes['position']

        page_pos = position['page']
        if page_pos == 'n':
            try:
                page = document.getobj(page_objid)['Kids'][0].objid
            except Exception:
                page = int(1)
        else:
            try:
                page = document.getobj(page_objid)['Kids'][int(page_pos) - 1].objid
            except Exception:
                MyLogger().my_logger().error('page not found...take the latest')
                pages_count = document.getobj(page_objid)['Count']
                page = document.getobj(page_objid)['Kids'][pages_count - 1].objid

        infodata = self.getdata(pdfdata1, info, prev, document).strip()
        rootdata = self.getdata(pdfdata1, root, prev, document).strip()
        pagedata = self.getdata(pdfdata1, page, prev, document).strip()

        no = size
        multiple_signs = False
        signatures = self.get_signature_names(document)
        if signatures.__len__() > 0:
            multiple_signs = True

        MyLogger().my_logger().info(f'visibility is {visibility}')
        if visibility == 'visible':
            rect_array = self.get_rect_array(pagedata, position)
            stream_name = compress(STREAM_WITH_NAME % udct[b'name'])
            if multiple_signs:
                objs = self.make_multi_visible_sig_objs(document, udct, no, page, pagedata, infodata, rootdata, stream_name, rect_array, zeros)
                xref = self.make_multi_visible_xref()
                new_size = 11
            else:
                objs = self.make_visible_sig_objs(udct, no, page, pagedata, infodata, rootdata, stream_name, rect_array, zeros)
                xref = self.make_visible_xref()
                new_size = 14
        else:
            if multiple_signs:
                objs = self.make_multi_inv_sig_objs(document, udct, no, page, pagedata, infodata, rootdata, zeros, signatures.__len__() + 1)
                xref = self.make_multi_inv_xref()
                new_size = 5
            else:
                objs = self.make_invisible_sig_objs(udct, no, page, pagedata, infodata, rootdata, zeros)
                xref = self.make_invisible_xref()
                new_size = 6

        pdfdata2 = b''.join(objs)
        startxref = len(pdfdata1)
        dct = {
            b'page': page,
            b'no': no,
            b'startxref': startxref + len(pdfdata2),
            b'prev': prev,
            b'info': no + 0,
            b'root': no + 1,
            b'size': no + new_size,
            b'p0': startxref + pdfdata2.find(b'\n%d 0 obj\n' % page) + 1,
        }
        for i in range(new_size):
            dct.update(({b'n%d' % i: startxref + pdfdata2.find(b'\n%d 0 obj\n' % (no + i)) + 1, }))

        trailer = b'''\
trailer
<</ID [<11><22>]/Info %(info)d 0 R/Prev %(prev)d/Root %(root)d 0 R/Size %(size)d>>\n\
startxref\n\
%(startxref)d\n\
%%%%EOF\n\
'''

        xref = xref % dct
        trailer = trailer % dct

        pdfdata2 = pdfdata2 + xref + trailer

        return pdfdata2

    def sign(self, datau, session, cert, cert_value, algomd, sig_attributes):
        MyLogger().my_logger().info('get certificate in format x509 to build signer attributes')
        x509 = Certificate.load(cert_value)
        time_stamp = self.get_timestamp()
        dct = {
            b'sigflags': 3,
            b'name': b'%b' % x509.subject.native['common_name'].encode(),
            b'signingdate': b'%b' % time_stamp.encode()
        }

        zeros = self.aligned(b'\0')

        MyLogger().my_logger().info('start building the new pdf')
        try:
            pdfdata2 = self.makepdf(datau, dct, zeros, sig_attributes)
            MyLogger().my_logger().info('pdf generated correctly')
        except Exception:
            raise PDFCreationError('Exception on creating pdf')

        MyLogger().my_logger().info('preparing data to be signed')
        startxref = len(datau)
        pdfbr1 = pdfdata2.find(zeros)
        pdfbr2 = pdfbr1 + len(zeros)
        br = [0, startxref + pdfbr1 - 1, startxref + pdfbr2 + 1, len(pdfdata2) - pdfbr2 - 1]
        brfrom = b'[0000000000 0000000000 0000000000 0000000000]'
        brto = b'[%010d %010d %010d %010d]' % tuple(br)
        pdfdata2 = pdfdata2.replace(brfrom, brto, 1)

        b1 = pdfdata2[:br[1] - startxref]
        b2 = pdfdata2[br[2] - startxref:]
        md = session.digestSession(Mechanism(LowLevel.CKM_SHA256))
        md.update(datau)
        md.update(b1)
        md.update(b2)
        md = bytes(md.final())
        MyLogger().my_logger().info('start pdf signing')
        try:
            contents = pdf_signer.sign(None, session, cert, cert_value, algomd, True, md)
            contents = self.aligned(contents)
            pdfdata2 = pdfdata2.replace(zeros, contents, 1)
            MyLogger().my_logger().info('pdf signed')
        except Exception:
            raise PDFSigningError('error in the sign procedure')

        return pdfdata2


def sign(datau, session, cert, cert_value, algomd, sig_attributes):
        cls = SignedData()
        return cls.sign(datau, session, cert, cert_value, algomd, sig_attributes)
