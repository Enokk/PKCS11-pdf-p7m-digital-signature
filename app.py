from my_logger import MyLogger
from os import path
from p7m_encoder import P7mEncoder
from signature_util import SignatureUtils


####################################################################
#       CONFIGURATION                                              #
####################################################################
# logger
logger = MyLogger.__call__().my_logger()
####################################################################


# Custom exceptions:
class P7mCreationError(Exception):
    ''' Raised when failing to create p7m '''
    pass


class App():

    @staticmethod
    def get_smart_cards_sessions():
        ''' Check for connected smart card

            Returns:
                a session list of connected smart cards
        '''
        # getting a smart card session
        return SignatureUtils().fetch_smart_card_sessions()

    @staticmethod
    def session_login(sessions, pin):
        ''' Attempt to login on connected smart cards

            Param:
                sessions: connected smart card slots
                pin: user pin

            Returns:
                logged in session
        '''
        
        # login on the session
        return SignatureUtils().user_login(sessions, pin)

    @staticmethod
    def sign_p7m(file_path, open_session):
        ''' Return a signed p7m file path
                The file name will be the same with .p7m at the end
                The path will be the same

            Param:
                file_path: complete or relative path of the file to sign
                open_session: logged in session (from login_attempt())
        '''

        # fetching file content
        file_content = App().get_file_content(file_path)
        # hashing file content
        file_content_digest = SignatureUtils().digest(open_session, file_content)

        # fetching smart card certificate
        certificate = SignatureUtils().fetch_certificate(open_session)
        # getting certificate value
        certificate_value = SignatureUtils().get_certificate_value(
            open_session, certificate)
        # hashing certificate value
        certificate_value_digest = SignatureUtils().digest(
            open_session, certificate_value)

        # getting signed attributes p7m field
        try:
            signed_attributes = P7mEncoder().encode_signed_attributes(
                file_content_digest, certificate_value_digest)
        except:
            raise P7mCreationError("Exception on encoding signed attributes")
        # getting bytes to be signed
        try:
            bytes_to_sign = P7mEncoder().bytes_to_sign(
                file_content_digest, certificate_value_digest)
        except:
            raise P7mCreationError("Exception on encoding bytes to sign")

        # fetching private key from smart card
        privKey = SignatureUtils().fetch_private_key(open_session, certificate)
        # signing bytes to be signed
        signed_attributes_signed = SignatureUtils().signature(
            open_session, privKey, bytes_to_sign)

        # getting issuer from certificate
        issuer = SignatureUtils().get_certificate_issuer(open_session, certificate)
        # getting serial number from certificate
        serial_number = SignatureUtils().get_certificate_serial_number(
            open_session, certificate)
        # getting signer info p7m field
        try:
            signer_info = P7mEncoder().encode_signer_info(
                issuer, serial_number, signed_attributes,
                signed_attributes_signed)
        except:
            raise P7mCreationError("Exception on encoding signer info")

        # create the p7m content
        try:
            output_content = P7mEncoder().make_a_p7m(
                file_content, certificate_value, signer_info)
        except:
            raise P7mCreationError("Exception on encoding p7m file content")

        # saves p7m to file
        signed_file_path = f"{file_path}.p7m"
        App().save_file_content(signed_file_path, output_content)

        return signed_file_path

    @staticmethod
    def session_logout(session):
        ''' User logout from session '''

        # logout from the session
        SignatureUtils().user_logout(session)

    @staticmethod
    def get_file_content(file_path):
        ''' Return `file_path` content in binary form '''

        logger.info(f"reading file {file_path}")
        with open(file_path, "rb") as file:
            file_content = file.read()

        return file_content

    @staticmethod
    def save_file_content(file_path, content):
        ''' Save content to `file_path` '''

        logger.info(f"saving output to {file_path}")
        with open(file_path, "wb") as file:
            file.write(content)
