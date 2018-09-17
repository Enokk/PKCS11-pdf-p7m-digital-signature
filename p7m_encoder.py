from asn1 import Encoder, Numbers, Classes
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

    def make_a_p7m(self, content, certificate_value, asn1_signer_info):
        ''' Return a well formed complete p7m.
            parameter content: file content to sign
            parameter certificate_value: value field of the smart card certificate
            parameter asn1_signer_info: signer info in asn1 form
        '''
        p7m = Encoder()
        p7m.start()

        p7m.enter(Numbers.Sequence)  # 1
        p7m.write(PKCS7_signed_data, Numbers.ObjectIdentifier)
        p7m.enter(zero_tag, Classes.Context)  # 2
        p7m.enter(Numbers.Sequence)  # 3
        p7m._emit(self._version_number())
        p7m._emit(self._digest_algorithm())
        p7m._emit(self._content_info(content))
        p7m.enter(zero_tag, Classes.Context)  # 4
        p7m._emit(self._certificates(bytes(certificate_value)))
        p7m.leave()  # 4
        p7m._emit(asn1_signer_info)
        p7m.leave()  # 3
        p7m.leave()  # 2
        p7m.leave()  # 1

        return p7m.output()

    def encode_signer_info(self, asn1_issuer, int_serial_number,
                           asn1_signed_attributes, signed_attributes_signed):
        ''' Return a well formed signer info (p7m field).
            parameter asn1_issuer: file content to sign
            parameter certificate_value: value field of the smart card certificate
            parameter asn1_signer_info: signer info in asn1 form
        '''
        signer_info = Encoder()
        signer_info.start()

        signer_info.enter(Numbers.Set)  # 1
        signer_info.enter(Numbers.Sequence)  # 2
        signer_info._emit(self._version_number())

        signer_info.enter(Numbers.Sequence)  # 3
        signer_info._emit(asn1_issuer)
        signer_info.write(int_serial_number, Numbers.Integer)
        signer_info.leave()  # 3

        signer_info.enter(Numbers.Sequence)  # 3
        signer_info.write(SHA256, Numbers.ObjectIdentifier)
        signer_info.write(0, Numbers.Null)
        signer_info.leave()  # 3

        signer_info._emit(asn1_signed_attributes)

        signer_info.enter(Numbers.Sequence)  # 3
        signer_info.write(RSA, Numbers.ObjectIdentifier)
        signer_info.write(0, Numbers.Null)
        signer_info.leave()  # 3

        signer_info.write(signed_attributes_signed, Numbers.OctetString)

        signer_info.leave()  # 2
        signer_info.leave()  # 1

        return signer_info.output()

    def asn1_signed_attributes(self, content_hash, certificate_hash):
        signed_attributes = Encoder()
        signed_attributes.start()

        signed_attributes.enter(zero_tag, Classes.Context)
        signed_attributes._emit(self.encode_signed_attributes(
            content_hash, certificate_hash))
        signed_attributes.leave()

        return signed_attributes.output()

    def to_sign_signed_attributes(self, content_hash, certificate_hash):
        signed_attributes = Encoder()
        signed_attributes.start()

        signed_attributes.enter(Numbers.Set)
        signed_attributes._emit(self.encode_signed_attributes(
            content_hash, certificate_hash))
        signed_attributes.leave()

        return signed_attributes.output()

    def encode_signed_attributes(self, content_hash, certificate_hash):
        signed_attributes = Encoder()
        signed_attributes.start()

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
        signed_attributes.write(bytes(content_hash), Numbers.OctetString)
        signed_attributes.leave()  # 2
        signed_attributes.leave()  # 1

        signed_attributes.enter(Numbers.Sequence)  # 1
        signed_attributes.write(signing_certificate_v2, Numbers.ObjectIdentifier)
        signed_attributes.enter(Numbers.Set)  # 2
        signed_attributes.enter(Numbers.Sequence)  # 3
        signed_attributes.enter(Numbers.Sequence)  # 4
        signed_attributes.enter(Numbers.Sequence)  # 5
        signed_attributes.enter(Numbers.Sequence)  # 6
        signed_attributes.write(SHA256, Numbers.ObjectIdentifier)
        signed_attributes.leave()  # 6
        signed_attributes.write(bytes(certificate_hash), Numbers.OctetString)
        signed_attributes.leave()  # 5
        signed_attributes.leave()  # 4
        signed_attributes.leave()  # 3
        signed_attributes.leave()  # 2
        signed_attributes.leave()  # 1

        return signed_attributes.output()

    def _version_number(self):
        version_number = Encoder()
        version_number.start()

        # Always 1
        version_number.write(1, Numbers.Integer)

        return version_number.output()

    def _digest_algorithm(self):
        digest_algorithm = Encoder()
        digest_algorithm.start()

        digest_algorithm.enter(Numbers.Set)  # 1
        digest_algorithm.enter(Numbers.Sequence)  # 2
        digest_algorithm.write(SHA256, Numbers.ObjectIdentifier)
        digest_algorithm.write(0, nr=Numbers.Null)
        digest_algorithm.leave()  # 2
        digest_algorithm.leave()  # 1

        return digest_algorithm.output()

    def _content_info(self, content):
        data_content = Encoder()
        data_content.start()

        data_content.enter(Numbers.Sequence)  # 1
        data_content.write(PKCS7, Numbers.ObjectIdentifier)
        data_content.enter(zero_tag, Classes.Context)  # 2
        data_content.write(content, Numbers.OctetString)
        data_content.leave()  # 2
        data_content.leave()  # 1

        return data_content.output()

    def _certificates(self, certificate_value):
        signing_certificete_v2 = Encoder()
        signing_certificete_v2.start()

        signing_certificete_v2._emit(certificate_value)

        return signing_certificete_v2.output()

    def _signer_info(self, signed_attributes):
        signer_info = Encoder()
        signer_info.start()

        signer_info.enter(Numbers.Set)  # 1
        signer_info.enter(Numbers.Sequence)  # 2
        signer_info._emit(self._version_number)
        signer_info._emit(self.__issuer())
        signer_info._emit(self.__digest_algorithm())
        signer_info._emit(signed_attributes)
        signer_info._emit(self.__signature_algorithm())
        signer_info._emit(self.__signature())
        signer_info.leave()  # 2
        signer_info.leave()  # 1

        return signer_info.output()

    def __issuer(self):
        issuer = Encoder()
        issuer.start()

        issuer.write(0, Numbers.Null)

        return issuer.output()

    def __digest_algorithm(self):
        digest_algorithm = Encoder()
        digest_algorithm.start()

        digest_algorithm.enter(Numbers.Sequence)  # 1
        digest_algorithm.write(SHA256, Numbers.ObjectIdentifier)
        digest_algorithm.write(0, Numbers.Null)
        digest_algorithm.leave()  # 1

        return digest_algorithm.output()

    def __signature_algorithm(self):
        signature_algorithm = Encoder()
        signature_algorithm.start()

        signature_algorithm.enter(Numbers.Sequence)  # 1
        signature_algorithm.write(RSA, Numbers.ObjectIdentifier)
        signature_algorithm.write(0, Numbers.Null)
        signature_algorithm.leave()  # 1

        return signature_algorithm.output()

    def __signature(self):
        signature = Encoder()
        signature.start()

        signature.write(0, Numbers.Null)

        return signature.output()

    @staticmethod
    def get_timestamp():
        timestamp = datetime.now().strftime("%y%m%d%H%M%SZ")
        return timestamp.encode()
