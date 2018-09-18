from asn1 import Encoder, Numbers, Classes
from console_output_util import log_print, dbg_print, err_print
import binascii
from datetime import datetime


####################################################################
#       CONFIGURATION                                              #
####################################################################
# UTCTime tag
UTCTime = 0x17
# [0] tag
zero_tag = 0x00
# List of SNMP values for asn1 tags
PKCS7 = "1.2.840.113549.1.7.1"
PKCS7_signed_data = "1.2.840.113549.1.7.2"
PKCS9_content_type = "1.2.840.113549.1.9.3"
PKCS9_message_digest = "1.2.840.113549.1.9.4"
SHA256 = "2.16.840.1.101.3.4.2.1"
RSA = "1.2.840.113549.1.1.1"
signing_time = "1.2.840.113549.1.9.5"
signing_certificate_v2 = "1.2.840.113549.1.9.16.2.47"
####################################################################


class P7mEncoder():

    def make_a_p7m(self, content, certificate_value, signer_info):
        '''
            Return a well formed complete p7m

            Param:
                content: file content to sign
                certificate_value: value field of the smart card certificate
                signer_info: signer info in asn1 form
        '''

        p7m = Encoder()
        p7m.start()

        log_print("encoding p7m")
        p7m.enter(Numbers.Sequence)  # 1
        p7m.write(PKCS7_signed_data, Numbers.ObjectIdentifier)
        p7m.enter(zero_tag, Classes.Context)  # 2
        p7m.enter(Numbers.Sequence)  # 3
        p7m._emit(self._version_number())
        p7m.enter(Numbers.Set)  # 4
        p7m._emit(self._digest_algorithm())
        p7m.leave()  # 4
        p7m._emit(self._content_info(content))
        p7m.enter(zero_tag, Classes.Context)  # 4
        p7m._emit(certificate_value)
        p7m.leave()  # 4
        p7m._emit(signer_info)
        p7m.leave()  # 3
        p7m.leave()  # 2
        p7m.leave()  # 1

        return p7m.output()

    def encode_signer_info(self, issuer, serial_number,
                           signed_attributes, signed_bytes):
        ''' Return a well formed signer info p7m field

            Params:
                issuer: smart card certificate issuer (bytes)
                serial_number: smart card serial number (int)
                signed_attributes: signed attributes p7m field
                signed_bytes: signature (bytes)
        '''

        signer_info = Encoder()
        signer_info.start()

        log_print("encoding signer info")
        signer_info.enter(Numbers.Set)  # 1
        signer_info.enter(Numbers.Sequence)  # 2
        signer_info._emit(self._version_number())

        signer_info.enter(Numbers.Sequence)  # 3
        signer_info._emit(issuer)
        signer_info.write(serial_number, Numbers.Integer)
        signer_info.leave()  # 3

        signer_info.enter(Numbers.Sequence)  # 3
        signer_info.write(SHA256, Numbers.ObjectIdentifier)
        signer_info.write(0, Numbers.Null)
        signer_info.leave()  # 3

        signer_info._emit(signed_attributes)

        signer_info.enter(Numbers.Sequence)  # 3
        signer_info.write(RSA, Numbers.ObjectIdentifier)
        signer_info.write(0, Numbers.Null)
        signer_info.leave()  # 3

        signer_info.write(signed_bytes, Numbers.OctetString)

        signer_info.leave()  # 2
        signer_info.leave()  # 1

        return signer_info.output()

    def encode_signed_attributes(self, content_hash, certificate_hash):
        ''' Return a well formed signed attributes p7m field

            Params:
                content_hash: content digest
                certificate_hash: certificate digest
        '''

        signed_attributes = Encoder()
        signed_attributes.start()

        log_print("encoding signed attributes")
        signed_attributes.enter(zero_tag, Classes.Context)
        signed_attributes._emit(self._get_signed_attributes(
            content_hash, certificate_hash))
        signed_attributes.leave()

        return signed_attributes.output()

    def bytes_to_sign(self, content_hash, certificate_hash):
        ''' Return the p7m part that needs to be signed

            Params:
                content_hash: content digest
                certificate_hash: certificate digest
        '''

        signed_attributes = Encoder()
        signed_attributes.start()

        log_print("building bytes to sign")
        signed_attributes.enter(Numbers.Set)
        signed_attributes._emit(self._get_signed_attributes(
            content_hash, certificate_hash))
        signed_attributes.leave()

        return signed_attributes.output()

    def _get_signed_attributes(self, content_hash, certificate_hash):
        ''' Return core signed attributes
                to get the p7m field call `encode_signed_attributes` instead
                to get the signature input call `bytes_to_sign` instead

            Params:
                content_hash: content digest
                certificate_hash: certificate digest
        '''

        signed_attributes = Encoder()
        signed_attributes.start()

        log_print("core signed attributes")
        signed_attributes.enter(Numbers.Sequence)  # 1
        signed_attributes.write(PKCS9_content_type, Numbers.ObjectIdentifier)
        signed_attributes.enter(Numbers.Set)  # 2
        signed_attributes.write(PKCS7, Numbers.ObjectIdentifier)
        signed_attributes.leave()  # 2
        signed_attributes.leave()  # 1

        signed_attributes.enter(Numbers.Sequence)  # 1
        signed_attributes.write(signing_time, Numbers.ObjectIdentifier)
        signed_attributes.enter(Numbers.Set)  # 2
        signed_attributes.write(self.get_timestamp(), UTCTime)
        signed_attributes.leave()  # 2
        signed_attributes.leave()  # 1

        signed_attributes.enter(Numbers.Sequence)  # 1
        signed_attributes.write(PKCS9_message_digest, Numbers.ObjectIdentifier)
        signed_attributes.enter(Numbers.Set)  # 2
        signed_attributes.write(content_hash, Numbers.OctetString)
        signed_attributes.leave()  # 2
        signed_attributes.leave()  # 1

        signed_attributes.enter(Numbers.Sequence)  # 1
        signed_attributes.write(signing_certificate_v2,
                                Numbers.ObjectIdentifier)
        signed_attributes.enter(Numbers.Set)  # 2
        signed_attributes.enter(Numbers.Sequence)  # 3
        signed_attributes.enter(Numbers.Sequence)  # 4
        signed_attributes.enter(Numbers.Sequence)  # 5
        signed_attributes.enter(Numbers.Sequence)  # 6
        signed_attributes.write(SHA256, Numbers.ObjectIdentifier)
        signed_attributes.leave()  # 6
        signed_attributes.write(certificate_hash, Numbers.OctetString)
        signed_attributes.leave()  # 5
        signed_attributes.leave()  # 4
        signed_attributes.leave()  # 3
        signed_attributes.leave()  # 2
        signed_attributes.leave()  # 1

        return signed_attributes.output()

    def _version_number(self):
        '''Return p7m version number field (always 1)'''
        version_number = Encoder()
        version_number.start()

        # Always 1
        version_number.write(1, Numbers.Integer)

        return version_number.output()

    def _digest_algorithm(self):
        '''Return p7m digest algorithm field (SHA256)'''
        digest_algorithm = Encoder()
        digest_algorithm.start()

        digest_algorithm.enter(Numbers.Sequence)  # 1
        digest_algorithm.write(SHA256, Numbers.ObjectIdentifier)
        digest_algorithm.write(0, Numbers.Null)
        digest_algorithm.leave()  # 1

        return digest_algorithm.output()

    def _content_info(self, content):
        '''Return p7m content info field'''

        data_content = Encoder()
        data_content.start()

        data_content.enter(Numbers.Sequence)  # 1
        data_content.write(PKCS7, Numbers.ObjectIdentifier)
        data_content.enter(zero_tag, Classes.Context)  # 2
        data_content.write(content, Numbers.OctetString)
        data_content.leave()  # 2
        data_content.leave()  # 1

        return data_content.output()

    @staticmethod
    def get_timestamp():
        ''' Return UTC timestamp in p7m compatible format '''

        timestamp = datetime.now().strftime("%y%m%d%H%M%SZ")
        return timestamp.encode()
