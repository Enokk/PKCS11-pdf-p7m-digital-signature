from PyKCS11 import PyKCS11Lib, Mechanism, LowLevel
from os import path, listdir, devnull, fsdecode
from console_output_util import log_print, dbg_print, err_print
import sys
import binascii


####################################################################
#       CONFIGURATION                                              #
####################################################################
# driver directory
driver_dir = "drivers"
####################################################################


class SignatureUtils:

    def fetch_smart_card_session(self):
        ''' Return a `session` on the connected smart card '''

        log_print("loading drivers")
        pkcs11 = PyKCS11Lib()
        for file in listdir(driver_dir):
            dbg_print("driver", fsdecode(file))
            pkcs11.load(file)
        #######################################
        # ^ BASTA DAVVERO CARICARLI TUTTI???? #
        #######################################
        #   sembra di sì                      #
        #######################################

        log_print("getting slots")  # check!!! show select popup???
        slot = pkcs11.getSlotList(tokenPresent=True)[0]
        dbg_print("slot mechanisms", pkcs11.getMechanismList(slot))
        log_print("opening session")
        return pkcs11.openSession(slot)

    def user_login(self, session, pin):
        ''' 
            User login on a `session` using `pin`

            Params:
                session: smart card session
                pin: user pin
        '''

        log_print("user login")
        try:
            session.login(pin)
            return None
        except:
            err_print("incorrect pin")
            return "error"

    def user_logout(self, session):
        ''' 
            User logout from a `session`

            Params:
                session: smart card session
        '''

        log_print("user logout")
        session.logout()

    def fetch_private_key(self, session):
        ''' 
            Return smart card private key reference

            Params:
                session: smart card session
        '''

        log_print("fetching privKey")
        # TODO check for right key
        privKey = session.findObjects(
            [(LowLevel.CKA_CLASS, LowLevel.CKO_PRIVATE_KEY)])[0]
        # if you don't print privKey you get a sign general error -.-
        print(privKey, file=open(devnull, "w"))  # to avoid general error
        dbg_print("private key", privKey)
        return privKey

    def fetch_public_key(self, session):
        ''' 
            Return smart card public key reference

            Params:
                session: smart card session
        '''

        log_print("fetching pubKey")
        pubKey = session.findObjects([(LowLevel.CKA_CLASS,
                                       LowLevel.CKO_PUBLIC_KEY)])[0]  # check???
        dbg_print("public key", pubKey)
        return pubKey

    def fetch_certificate(self, session):
        ''' 
            Return smart card certificate

            Params:
                session: smart card session
        '''

        log_print("fetching certificate")
        certificates = session.findObjects(
            [(LowLevel.CKA_CLASS, LowLevel.CKO_CERTIFICATE)])
        # TODO check for right certificate
        certificate = certificates[1]
        dbg_print("certificate", certificate)
        return certificate

    def get_certificate_value(self, session, certificate):
        ''' 
            Return the value of `certificate`

            Params:
                session: smart card session
                certificate: smart card certificate
        '''

        log_print("fetching certificate value")
        certificate_value = session.getAttributeValue(
            certificate, [LowLevel.CKA_VALUE])[0]
        dbg_print("certificate value", binascii.hexlify(
            bytes(certificate_value)))
        return bytes(certificate_value)

    def get_certificate_issuer(self, session, certificate):
        ''' 
            Return the issuer of `certificate`

            Params:
                session: smart card session
                certificate: smart card certificate
        '''

        log_print("fetching certificate issuer")
        certificate_issuer = session.getAttributeValue(
            certificate, [LowLevel.CKA_ISSUER])[0]
        dbg_print("certificate issuer", binascii.hexlify(
            bytes(certificate_issuer)))
        return bytes(certificate_issuer)

    def get_certificate_serial_number(self, session, certificate):
        ''' 
            Return the serial number of `certificate`

            Params:
                session: smart card session
                certificate: smart card certificate
        '''

        log_print("fetching certificate serial number")
        serial_number = session.getAttributeValue(
            certificate, [LowLevel.CKA_SERIAL_NUMBER])[0]
        int_serial_number = int.from_bytes(
            serial_number, byteorder='big', signed=True)
        dbg_print("certificate serial number", str(int_serial_number))
        return int_serial_number

    def digest(self, session, content):
        ''' 
            Return `content` hash

            Params:
                session: smart card session
                content: content to hash
        '''

        log_print("hashing content")
        digest = session.digest(content, Mechanism(LowLevel.CKM_SHA256))
        dbg_print("digest", binascii.hexlify(bytes(digest)))
        return bytes(digest)

    def signature(self, session, privKey, content):
        ''' 
            Sign `content` with `privKey` reference

            Reurn:
                signature in bytearray

            Params:
                session: smart card session.
                privKey: reference to the smart card private key.
                content: bytes to hash and sign
        '''

        log_print("signing content")
        signature = session.sign(privKey, content, Mechanism(
            LowLevel.CKM_SHA256_RSA_PKCS, None))
        dbg_print("signature", binascii.hexlify(bytes(signature)))
        return bytes(signature)
