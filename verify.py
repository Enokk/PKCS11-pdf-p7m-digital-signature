# *-* coding: utf-8 *-*
import verifier


def verify(pdfdata, certs=None):
    '''
        Return the Hash, Signature and Cert verification result for each signature in the pdf

        Params:
            pdfdata: Pdf content as bytes
            certs: List of certificates
    '''
    verifier_results = []
    n = 0
    byte_ranges_count = pdfdata.count(b'/ByteRange')
    for i in range(byte_ranges_count):
        n = pdfdata.find(b'/ByteRange', n)
        start = pdfdata.find(b'[', n)
        stop = pdfdata.find(b']', start)
        assert n != -1 and start != -1 and stop != -1
        br = [int(i, 10) for i in pdfdata[start + 1:stop].split()]
        contents = pdfdata[br[0] + br[1] + 1:br[2] - 1]
        data = []
        for i in range(0, len(contents), 2):
            data.append(int(contents[i:i + 2], 16))
        bcontents = bytes(data)
        data1 = pdfdata[br[0]: br[0] + br[1]]
        data2 = pdfdata[br[2]: br[2] + br[3]]
        signedData = data1 + data2
        verifier_results.append(verifier.verify(bcontents, signedData, certs))
        n = stop
    return verifier_results
