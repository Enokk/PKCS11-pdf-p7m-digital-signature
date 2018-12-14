from asn1crypto import cms
from datetime import datetime
from mimetypes import MimeTypes
from my_logger import MyLogger
from OpenSSL import crypto
from os import path
from p7m_encoder import P7mEncoder, P7mAttributes
from signature_util import SignatureUtils
from tkinter import Tk, Label, Button, Frame
from verify import verify
import pdf_builder



# Custom exceptions:
class P7mCreationError(Exception):
    ''' Raised when failing to create p7m '''
    pass

class PdfVerificationError(Exception):
    pass

class CertificateValidityError(Exception):
    ''' Raised for validity problems on the certificate '''
    pass

class CertificateOwnerException(Exception):
    ''' Raised if user_cf is not equal to smart card cf '''
    pass



class DigiSignLib():
    PROCEED = None

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
    def sign_pdf(file_path, open_session, user_cf, sig_attributes):
        ''' Return a signed pdf file path
                The file name will be the same with (firmato) before the extension and .pdf at the end
                The path will be the same

            Param:
                file_path: complete or relative path of the file to sign
                open_session: logged in session (from login_attempt())
        '''
        # fetching smart card certificate
        certificate = SignatureUtils.fetch_certificate(open_session)
        # getting certificate value
        certificate_value = SignatureUtils.get_certificate_value(
            open_session, certificate)

        # check for signer identity
        # if user_cf == "X" * 15, avoid this check
        if user_cf != "X" * 15:
            # only for REST calls
            DigiSignLib()._check_certificate_owner(certificate_value, user_cf)

        # check for certificate time validity
        DigiSignLib()._check_certificate_validity(certificate_value)

        MyLogger().my_logger().info(f"reading pdf file {file_path}")
        datau = open(file_path, 'rb').read()
        datas = pdf_builder.sign(datau, open_session, certificate, certificate_value, 'sha256', sig_attributes)

        signed_file_path = DigiSignLib().get_signed_files_path(file_path, 'pdf')

        MyLogger().my_logger().info(f"saving output to {signed_file_path}")
        with open(signed_file_path, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        MyLogger().my_logger().info(f"verifying pdf signatures of {signed_file_path}")
        try:
            new_data = open(signed_file_path, 'rb').read()
            results = verify(new_data, [certificate_value])
            for key, res in enumerate(results, start=1):
                print('Signature %d: ' % key, res)
                MyLogger().my_logger().info(f"Signature {key}: {res}")
                if not res['hashok?']:
                    raise PdfVerificationError(f"Hash verification of Signature {key} is failed.")
                if not res['signatureok?']:
                    raise PdfVerificationError(f"Signature verification of Signature {key} is failed.")
                if not res['certok?']:
                    # TODO verify certificates
                    MyLogger().my_logger().error(f"Certificate verification of Signature {key} is failed.")
        except:
            MyLogger().my_logger().error(f"Error during verification of Signature {key}:")
            raise

        return signed_file_path

    @staticmethod
    def sign_p7m(file_path, open_session, user_cf, sig_attrs):
        ''' Return a signed p7m file path
                The file name will be the same with (firmato) before the extension and .p7m at the end
                The path will be the same

            Param:
                file_path: complete or relative path of the file to sign
                open_session: logged in session (from login_attempt())
        '''

        # fetching sig type
        sig_type = sig_attrs['p7m_sig_type']
        # fetching file content
        file_content = DigiSignLib().get_file_content(file_path)
        # check existing signatures
        p7m_attrs = P7mAttributes(b'', b'', b'')
        mime = MimeTypes().guess_type(file_path)[0]
        if mime == 'application/pkcs7':
            info = cms.ContentInfo.load(file_content)
            # retrieving existing signatures attributes
            signed_data = info['content']
            p7m_attrs.algos = signed_data['digest_algorithms'].contents
            p7m_attrs.certificates = signed_data['certificates'].contents
            #
            if sig_type == 'parallel':
                p7m_attrs.signer_infos = signed_data['signer_infos'].contents
                file_content = signed_data['encap_content_info'].native['content']

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

        # check for signer identity
        # if user_cf == "X" * 15, avoid this check
        if user_cf != "X" * 15:
            # only for REST calls
            DigiSignLib()._check_certificate_owner(certificate_value, user_cf)

        # check for certificate time validity
        DigiSignLib()._check_certificate_validity(certificate_value)

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
                signed_attributes_signed, p7m_attrs.signer_infos)
        except:
            raise P7mCreationError("Exception on encoding signer info")

        # create the p7m content
        try:
            output_content = P7mEncoder().make_a_p7m(
                file_content, certificate_value, signer_info, p7m_attrs)
        except:
            raise P7mCreationError("Exception on encoding p7m file content")

        # saves p7m to file
        signed_file_path = DigiSignLib().get_signed_files_path(file_path, 'p7m', sig_type)
        DigiSignLib().save_file_content(signed_file_path, output_content)

        return signed_file_path


    @staticmethod
    def session_logout(session):
        ''' User logout from session '''

        # logout from the session
        SignatureUtils().user_logout(session)


    @staticmethod
    def session_close(session):
        ''' Close smart card `session` '''

        # session close
        SignatureUtils().close_session(session)


    @staticmethod
    def get_file_content(file_path):
        ''' Return `file_path` content in binary form '''

        MyLogger().my_logger().info(f"reading file {file_path}")
        with open(file_path, "rb") as file:
            file_content = file.read()

        return file_content


    @staticmethod
    def save_file_content(file_path, content):
        ''' Save content to `file_path` '''

        MyLogger().my_logger().info(f"saving output to {file_path}")
        with open(file_path, "wb") as file:
            file.write(content)


    @staticmethod
    def _check_certificate_validity(certificate_value):
        MyLogger().my_logger().info("Chech for certificate time validity")
        certificate_x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, bytes(certificate_value))
        # [2:14] gets rid of "b'" at the beginning and "##Z" at the end
        # precision in minutes
        notBefore = str(certificate_x509.get_notBefore())[2:14]
        notAfter = str(certificate_x509.get_notAfter())[2:14]
        current_time = int(datetime.now().strftime("%Y%m%d%H%M"))

        try:
            diff = current_time - int(notBefore)
        except:
            raise ValueError(f"Impossible to cast {notBefore} to int")

        # <= for safety
        if diff <= 0:
            DigiSignLib()._not_valid_yet_popup()
            raise CertificateValidityError("Certificate not valid yet")

        try:
            diff = int(notAfter) - current_time
        except:
            raise ValueError(f"Impossible to cast {notAfter} to int")

        # <= for safety
        if diff <= 0:
            DigiSignLib().PROCEED = None
            DigiSignLib()._proceed_with_expired_certificate()
            if DigiSignLib().PROCEED == None:
                MyLogger().my_logger().error("PROCEED is still None")
                raise ValueError("Something went wrong with the expired certificate choise popup")
            if not DigiSignLib().PROCEED:
                MyLogger().my_logger().warning("User chosen to NOT proceed")
                raise CertificateValidityError("Certificate expired")
        MyLogger().my_logger().info("User chosen to proceed")


    @staticmethod
    def _check_certificate_owner(certificate_value, user_cf):
        ''' Check if user_cf is equal to smart card cf. Raise a `CertificateOwnerException` '''

        MyLogger().my_logger().info("Chech for certificate owner")
        certificate_x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, bytes(certificate_value))

        subject = certificate_x509.get_subject()
        components = dict(subject.get_components())
        component = components[bytes("serialNumber".encode())]
        codice_fiscale = component.decode()[-16:]

        if codice_fiscale.upper() != user_cf.upper():
            raise CertificateOwnerException(f"{user_cf} (input) != {codice_fiscale} (smartcard)")
        else:
            MyLogger().my_logger().info("owner verified")


    @staticmethod
    def _not_valid_yet_popup():
        ''' Little popup for telling the user that his certificate is not valid yet '''

        MyLogger().my_logger().info("Certificate not valid yet")
        widget = Tk()
        row = Frame(widget)
        label1 = Label(row, text="Il certificato di firma non è ancora valido,")
        label2 = Label(row, text="firma digitale annullata")
        row.pack(side="top", padx=60, pady=20)
        label1.pack(side="top")
        label2.pack(side="top")

        def on_click():
            widget.destroy()

        button = Button(widget, command=on_click, text="OK")
        button.pack(side="top", fill="x", padx=120)
        filler = Label(widget, height=1, text="")
        filler.pack(side="top")

        widget.title("Warning")
        widget.attributes("-topmost", True)
        widget.update()
        DigiSignLib()._center(widget)
        widget.mainloop()


    @classmethod
    def _proceed_with_expired_certificate(cls):
        ''' Little popup for asking the user if he wants to sign with an expired dertificate '''

        MyLogger().my_logger().info("Certificate expired")
        widget = Tk()
        row1 = Frame(widget)
        label1 = Label(row1, text="Il certificato di firma risulta scaduto,")
        label2 = Label(row1, text="procedere comunque?")
        row1.pack(side="top", padx=60, pady=20)
        label1.pack(side="top")
        label2.pack(side="top")

        def on_click_ok():
            widget.destroy()
            cls.PROCEED = True

        def on_click_nok():
            widget.destroy()
            cls.PROCEED = False

        row2 = Frame(widget)
        button_ok = Button(row2, width=10, command=on_click_ok, text="OK")
        button_nok = Button(row2, width=10, command=on_click_nok, text="Annulla")
        row2.pack(side="top")
        button_ok.pack(side="left", padx=10)
        button_nok.pack(side="right", fill="x", padx=10)
        filler = Label(widget, height=1, text="")
        filler.pack(side="top")

        widget.title("Warning")
        widget.attributes("-topmost", True)
        widget.update()
        DigiSignLib()._center(widget)
        widget.mainloop()


    @staticmethod
    def _center(widget):
        ''' Center `widget` on the screen '''
        screen_width = widget.winfo_screenwidth()
        screen_height = widget.winfo_screenheight()

        x = screen_width / 2 - widget.winfo_width() / 2
        # Little higher than center
        y = screen_height / 2 - widget.winfo_height()

        widget.geometry(f"+{int(x)}+{int(y)}")


    @staticmethod
    def get_signed_files_path(file_path, sig_type, p7m_sig_type=None):
        #   extracting needed part of file path
        signed_file_base_path = path.dirname(file_path)
        signed_file_complete_name = path.basename(file_path)
        signed_file_name, signed_file_extension = path.splitext(signed_file_complete_name)
        #   composing final file name
        start = signed_file_name.find('firmato')
        if start != -1:
            signed_file_name = signed_file_name.replace('firmato', '')
            final_file_name = f"{signed_file_name[:start]}(firmato){signed_file_name[start:]}{signed_file_extension}"
        else:
            final_file_name = f"{signed_file_name}(firmato){signed_file_extension}"
        if p7m_sig_type != 'parallel' and sig_type != 'pdf':
            final_file_name = final_file_name + f".{sig_type}"
        signed_file_path = path.join(signed_file_base_path, final_file_name)
        return signed_file_path
