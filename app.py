from signature_util import SignatureUtils
from p7m_encoder import P7mEncoder
from console_output_util import log_print, dbg_print, err_print
from os import path
import binascii


####################################################################
#       CONFIGURATION                                              #
####################################################################
#
####################################################################


class App:

    @staticmethod
    def sign_p7m(file_path, pin):
        ''' Return a signed p7m file path
                The file name will be the same with .p7m at the end
                The path will be the same

            Param:
                file_path: complete or relative path of the file to sign
                pin: smart card user pin
        '''

        # getting a smart card session
        try:
            sessions = SignatureUtils.fetch_smart_card_sessions()
        except:
            raise

        # login on the session
        try:
            session = SignatureUtils.user_login(sessions, pin)
        except:
            raise

        # fetching file content
        file_content = App().get_file_content(file_path)
        if file_content == None:
            err_print("Exit signature procedure!")
            exit
        # hashing file content
        file_content_digest = SignatureUtils.digest(session, file_content)

        # fetching smart card certificate
        certificate = SignatureUtils.fetch_certificate(session)
        # getting certificate value
        certificate_value = SignatureUtils.get_certificate_value(
            session, certificate)
        # hashing certificate value
        certificate_value_digest = SignatureUtils.digest(
            session, certificate_value)

        # getting signed attributes p7m field
        signed_attributes = P7mEncoder.encode_signed_attributes(
            file_content_digest, certificate_value_digest)
        # getting bytes to be signed
        bytes_to_sign = P7mEncoder.bytes_to_sign(
            file_content_digest, certificate_value_digest)

        # fetching private key from smart card
        privKey = SignatureUtils.fetch_private_key(session, certificate)
        # signing bytes to be signed
        signed_attributes_signed = SignatureUtils.signature(
            session, privKey, bytes_to_sign)

        # getting issuer from certificate
        issuer = SignatureUtils.get_certificate_issuer(session, certificate)
        # getting serial number from certificate
        serial_number = SignatureUtils.get_certificate_serial_number(
            session, certificate)
        # getting signer info p7m field
        signer_info = P7mEncoder.encode_signer_info(
            issuer, serial_number, signed_attributes,
            signed_attributes_signed)

        # create the p7m content
        output_content = P7mEncoder.make_a_p7m(
            file_content, certificate_value, signer_info)

        # saves p7m to file
        signed_file_path = f"{file_path}.p7m"
        App().save_file_content(signed_file_path, output_content)

        # logout from the session
        SignatureUtils.user_logout(session)

        return signed_file_path

    @staticmethod
    def get_file_content(file_path):
        ''' Return `file_path` content in binary form '''

        log_print(f"reading file {file_path}")
        try:
            with open(file_path, "rb") as file:
                file_content = file.read()
                dbg_print("file_content", f"[{file_content}]")
        except:
            raise
        
        return file_content

    @staticmethod
    def save_file_content(file_path, content):
        ''' Save content to `file_path` '''
        log_print(f"saving output to {file_path}")

        try:
            with open(file_path, "wb") as file:
                file.write(content)
        except:
            raise
