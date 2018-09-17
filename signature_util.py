from PyKCS11 import PyKCS11Lib, Mechanism, LowLevel
from os import path, devnull
from console_output_util import log_print, dbg_print, err_print
import sys
import binascii


####################################################################
#       CONFIGURATION                                              #
####################################################################
#
####################################################################


class SignatureUtils:

    def __init__(self):
        self.drivers = {
            "pkcs11_dll_i": path.join(".", "driver", "bit4ipki.dll"),
            "pkcs11_dll_x": path.join(".", "driver", "bit4xpki.dll")
        }
        dbg_print("driver paths", self.drivers)

    def fetch_smart_card_session(self):
        ''' Return a session on the connected smart card '''

        # loading drivers
        log_print("loading drivers")
        pkcs11 = PyKCS11Lib()
        for driver in self.drivers:
            pkcs11.load(self.drivers[driver])
        #######################################
        # ^ BASTA DAVVERO CARICARLI TUTTI???? #
        #######################################
        #   sembra di sì                      #
        #######################################

        # opening session
        log_print("getting slots")  # check!!! show select popup???
        slot = pkcs11.getSlotList(tokenPresent=True)[0]
        dbg_print("slot mechanisms", pkcs11.getMechanismList(slot))
        log_print("opening session")
        return pkcs11.openSession(slot)

    def user_login(self, session, pin):
        ''' User login on a session.
            param session: smart card session
        '''

        log_print("user login")
        try:
            session.login(pin)  # to keep in memory!!!
            return None
        except:
            err_print("incorrect pin")
            return "error"

    def user_logout(self, session):
        ''' User logout from a session.
            param session: smart card session
        '''

        log_print("user logout")
        session.logout()

    def fetch_private_key(self, session):
        ''' Return smart card private key reference.
            param session: smart card session
        '''

        log_print("fetching privKey")
        privKey = session.findObjects(
            [(LowLevel.CKA_CLASS, LowLevel.CKO_PRIVATE_KEY)])[0]  # check???
        # if you don't print privKey you get a sign general error -.-
        print(privKey, file=open(devnull, "w"))  # to avoid general error
        dbg_print("private key", privKey)
        return privKey

    def fetch_public_key(self, session):
        ''' Return smart card public key reference.
            param session: smart card session
        '''

        log_print("fetching pubKey")
        pubKey = session.findObjects([(LowLevel.CKA_CLASS,
            LowLevel.CKO_PUBLIC_KEY)])[0]  # check???
        dbg_print("public key", pubKey)
        return pubKey

    def fetch_certificate(self, session):
        ''' Return smart card certificate.
            param session: smart card session
        '''

        log_print("fetching certificate")
        certificates = session.findObjects(
            [(LowLevel.CKA_CLASS, LowLevel.CKO_CERTIFICATE)])
        certificate = certificates[1]
        dbg_print("certificate", certificate)
        return certificate

    def get_certificate_value(self, session, certificate):
        ''' Return certificate value.
            param session: smart card session
            param certificate: smart card certificate
        '''

        log_print("fetching certificate value")
        certificate_value = session.getAttributeValue(
            certificate, [LowLevel.CKA_VALUE])[0]
        dbg_print("certificate value", binascii.hexlify(
            bytearray(certificate_value)))
        return certificate_value

    def get_certificate_issuer(self, session, certificate):
        ''' Return certificate issuer.
            param session: smart card session
            param certificate: smart card certificate
        '''

        log_print("fetching certificate issuer")
        certificate_issuer = session.getAttributeValue(
            certificate, [LowLevel.CKA_ISSUER])[0]
        dbg_print("certificate issuer", binascii.hexlify(
            bytearray(certificate_issuer)))
        return certificate_issuer
    
    def get_certificate_serial_number(self, session, certificate):
        ''' Return certificate serial number.
            param session: smart card session
            param certificate: smart card certificate
        '''

        log_print("fetching certificate serial number")
        certificate_serial_number = session.getAttributeValue(
            certificate, [LowLevel.CKA_SERIAL_NUMBER])[0]
        dbg_print("certificate serial number", binascii.hexlify(
            bytearray(certificate_serial_number)))
        return certificate_serial_number

    def digest(self, session, content):
        ''' Return the hash of content.
            param session: smart card session
            param content: content to hash
        '''

        log_print("hashing content")
        digest = session.digest(content, Mechanism(LowLevel.CKM_SHA256))
        dbg_print("digest", binascii.hexlify(bytearray(digest)))
        return digest

    def signature(self, session, privKey, content):
        ''' Sign content with privKey reference in the session.

            Reurn: signature in bytearray.

            param session: smart card session.
            param privKey: reference to the smart card private key.
            param content: bytes to hash and sign
        '''

        log_print("signing content")
        signature = session.sign(privKey, content, Mechanism(
            LowLevel.CKM_SHA256_RSA_PKCS, None))
        dbg_print("signature", binascii.hexlify(bytearray(signature)))
        return signature
