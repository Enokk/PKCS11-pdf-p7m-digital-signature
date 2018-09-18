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

        my_signer = SignatureUtils()
        my_p7m_encoder = P7mEncoder()

        # getting a smart card session
        session = my_signer.fetch_smart_card_session()

        # login on the session
        error = my_signer.user_login(session, pin)
        if error != None:
            err_print("Exit signature procedure!")
            exit

        # fetching file content
        file_content = App().get_file_content(file_path)
        if file_content == None:
            err_print("Exit signature procedure!")
            exit
        # hashing file content
        file_content_digest = my_signer.digest(session, file_content)

        # fetching smart card certificate
        certificate = my_signer.fetch_certificate(session)
        # getting certificate value
        certificate_value = my_signer.get_certificate_value(
            session, certificate)
        # hashing certificate value
        certificate_value_digest = my_signer.digest(
            session, certificate_value)

        # getting signed attributes p7m field
        signed_attributes = my_p7m_encoder.encode_signed_attributes(
            file_content_digest, certificate_value_digest)
        # getting bytes to be signed
        bytes_to_sign = my_p7m_encoder.bytes_to_sign(
            file_content_digest, certificate_value_digest)

        # fetching private key from smart card
        privKey = my_signer.fetch_private_key(session)
        # signing bytes to be signed
        signed_attributes_signed = my_signer.signature(
            session, privKey, bytes_to_sign)

        # getting issuer from certificate
        issuer = my_signer.get_certificate_issuer(session, certificate)
        # getting serial number from certificate
        serial_number = my_signer.get_certificate_serial_number(
            session, certificate)
        # getting signer info p7m field
        signer_info = my_p7m_encoder.encode_signer_info(
            issuer, serial_number, signed_attributes,
            signed_attributes_signed)

        # create the p7m content
        output_content = my_p7m_encoder.make_a_p7m(
            file_content, certificate_value, signer_info)

        # saves p7m to file
        signed_file_path = f"{file_path}.p7m"
        App().save_file_content(signed_file_path, output_content)

        # logout from the session
        my_signer.user_logout(session)

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
            err_print("impossibile aprire il file {file_path}")
            file_content = None
        finally:
            return file_content

    @staticmethod
    def save_file_content(file_path, content):
        ''' Save content to `file_path` '''
        log_print(f"saving output to {file_path}")

        try:
            with open(file_path, "wb") as file:
                file.write(content)
        except:
            err_print("impossibile aprire il file {file_path}")
