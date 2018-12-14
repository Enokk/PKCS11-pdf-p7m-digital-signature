from asn1 import Encoder, Numbers, Classes
from datetime import datetime
from my_logger import MyLogger



####################################################################
#       CONFIGURATION                                              #
####################################################################
# UTCTime tag
UTC_TIME = 0x17
# [0] tag
ZERO_TAG = 0x00
# List of SNMP values for asn1 tags
PKCS7 = "1.2.840.113549.1.7.1"
PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2"
PKCS9_CONTENT_TYPE = "1.2.840.113549.1.9.3"
PKCS9_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
SHA256 = "2.16.840.1.101.3.4.2.1"
RSA = "1.2.840.113549.1.1.1"
SIGNING_TIME = "1.2.840.113549.1.9.5"
SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"
####################################################################


class P7mAttributes:
    def __init__(self, algos, certificates, signer_infos):
        self.algos = algos
        self.certificates = certificates
        self.signer_infos = signer_infos


class P7mEncoder:

    @staticmethod
    def make_a_p7m(content, certificate_value, signer_info, p7m_sig_attrs: P7mAttributes):
        '''
            Return a well formed complete p7m

            Param:
                content: file content to sign
                certificate_value: value field of the smart card certificate
                signer_info: signer info in asn1 form
                p7m_sig_attrs: existing p7m signatures attributes
        '''

        p7m = Encoder()
        p7m.start()

        MyLogger().my_logger().info("encoding p7m")
        p7m.enter(Numbers.Sequence)  # 1
        p7m.write(PKCS7_SIGNED_DATA, Numbers.ObjectIdentifier)
        p7m.enter(ZERO_TAG, Classes.Context)  # 2
        p7m.enter(Numbers.Sequence)  # 3
        p7m._emit(P7mEncoder._version_number())
        p7m.enter(Numbers.Set)  # 4
        p7m._emit(P7mEncoder._digest_algorithm() + p7m_sig_attrs.algos)
        p7m.leave()  # 4
        p7m._emit(P7mEncoder._content_info(content))
        p7m.enter(ZERO_TAG, Classes.Context)  # 4
        p7m._emit(certificate_value + p7m_sig_attrs.certificates)
        p7m.leave()  # 4
        p7m._emit(signer_info)
        p7m.leave()  # 3
        p7m.leave()  # 2
        p7m.leave()  # 1

        return p7m.output()


    @staticmethod
    def encode_signer_info(issuer, serial_number,
                           signed_attributes, signed_bytes, existing_sig_infos):
        ''' Return a well formed signer info p7m field

            Params:
                issuer: smart card certificate issuer (bytes)
                serial_number: smart card serial number (int)
                signed_attributes: signed attributes p7m field
                signed_bytes: signature (bytes)
        '''

        signer_info = Encoder()
        signer_info.start()

        MyLogger().my_logger().info("encoding signer info")
        signer_info.enter(Numbers.Set)  # 1
        signer_info.enter(Numbers.Sequence)  # 2
        signer_info._emit(P7mEncoder._version_number())

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
        if existing_sig_infos != b'':
            signer_info._emit(existing_sig_infos)
        signer_info.leave()  # 1

        return signer_info.output()


    @staticmethod
    def encode_signed_attributes(content_hash, certificate_hash):
        ''' Return a well formed signed attributes p7m field

            Params:
                content_hash: content digest
                certificate_hash: certificate digest
        '''

        signed_attributes = Encoder()
        signed_attributes.start()

        MyLogger().my_logger().info("encoding signed attributes")
        signed_attributes.enter(ZERO_TAG, Classes.Context)
        signed_attributes._emit(P7mEncoder._get_signed_attributes(
            content_hash, certificate_hash))
        signed_attributes.leave()

        return signed_attributes.output()


    @staticmethod
    def bytes_to_sign(content_hash, certificate_hash):
        ''' Return the p7m part that needs to be signed

            Params:
                content_hash: content digest
                certificate_hash: certificate digest
        '''

        signed_attributes = Encoder()
        signed_attributes.start()

        MyLogger().my_logger().info("building bytes to sign")
        signed_attributes.enter(Numbers.Set)
        signed_attributes._emit(P7mEncoder._get_signed_attributes(
            content_hash, certificate_hash))
        signed_attributes.leave()

        return signed_attributes.output()


    @staticmethod
    def _get_signed_attributes(content_hash, certificate_hash):
        ''' Return core signed attributes
                to get the p7m field call `encode_signed_attributes` instead
                to get the signature input call `bytes_to_sign` instead

            Params:
                content_hash: content digest
                certificate_hash: certificate digest
        '''

        signed_attributes = Encoder()
        signed_attributes.start()

        signed_attributes.enter(Numbers.Sequence)  # 1
        signed_attributes.write(PKCS9_CONTENT_TYPE, Numbers.ObjectIdentifier)
        signed_attributes.enter(Numbers.Set)  # 2
        signed_attributes.write(PKCS7, Numbers.ObjectIdentifier)
        signed_attributes.leave()  # 2
        signed_attributes.leave()  # 1

        signed_attributes.enter(Numbers.Sequence)  # 1
        signed_attributes.write(SIGNING_TIME, Numbers.ObjectIdentifier)
        signed_attributes.enter(Numbers.Set)  # 2
        signed_attributes.write(P7mEncoder._get_timestamp(), UTC_TIME)
        signed_attributes.leave()  # 2
        signed_attributes.leave()  # 1

        signed_attributes.enter(Numbers.Sequence)  # 1
        signed_attributes.write(PKCS9_MESSAGE_DIGEST, Numbers.ObjectIdentifier)
        signed_attributes.enter(Numbers.Set)  # 2
        signed_attributes.write(content_hash, Numbers.OctetString)
        signed_attributes.leave()  # 2
        signed_attributes.leave()  # 1

        signed_attributes.enter(Numbers.Sequence)  # 1
        signed_attributes.write(SIGNING_CERTIFICATE_V2,
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


    @staticmethod
    def _version_number():
        '''Return p7m version number field (always 1)'''
        version_number = Encoder()
        version_number.start()

        # Always 1
        version_number.write(1, Numbers.Integer)

        return version_number.output()


    @staticmethod
    def _digest_algorithm(algo=SHA256):
        '''Return p7m digest algorithm field (default SHA256)'''
        digest_algorithm = Encoder()
        digest_algorithm.start()

        digest_algorithm.enter(Numbers.Sequence)  # 1
        digest_algorithm.write(algo, Numbers.ObjectIdentifier)
        digest_algorithm.write(0, Numbers.Null)
        digest_algorithm.leave()  # 1

        return digest_algorithm.output()


    @staticmethod
    def _content_info(content):
        '''Return p7m content info field'''

        data_content = Encoder()
        data_content.start()

        data_content.enter(Numbers.Sequence)  # 1
        data_content.write(PKCS7, Numbers.ObjectIdentifier)
        data_content.enter(ZERO_TAG, Classes.Context)  # 2
        data_content.write(content, Numbers.OctetString)
        data_content.leave()  # 2
        data_content.leave()  # 1

        return data_content.output()


    @staticmethod
    def _get_timestamp():
        ''' Return UTC timestamp in p7m compatible format '''

        timestamp = datetime.now().strftime("%y%m%d%H%M%SZ")
        return timestamp.encode()
