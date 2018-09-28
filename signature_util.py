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

    @staticmethod
    def fetch_smart_card_sessions():
        ''' Return a `session` list for the connected smart cards '''

        log_print("loading drivers")
        pkcs11 = PyKCS11Lib()
        for file in listdir(driver_dir):
            dbg_print("driver", fsdecode(file))
            pkcs11.load(file)

        try:
            slots = SignatureUtils._fetch_slots(pkcs11)
        except:
            raise

        sessions = []
        for slot in slots:
            try:
                log_print(f"opening session for slot{slot}")
                session = pkcs11.openSession(slot)
                sessions.append(session)
            except:
                continue

        if(len(sessions) < 1):
            raise ConnectionError("Impossible to open a session")

        return sessions

    @staticmethod
    def _fetch_slots(pkcs11_lib):
        ''' Return a `slot list` (connected Smart Cards) '''

        log_print("getting slots")
        try:
            slots = pkcs11_lib.getSlotList(tokenPresent=True)
            if(len(slots) < 1):
                raise ConnectionError("No Smart Card slot found!")
            else:
                return slots
        except:
            raise

    @staticmethod
    def user_login(sessions, pin):
        ''' 
            User login on a `session` using `pin`

            Params:
                sessions: smart card session list
                pin: user pin

            Returns:
                the logged in session
        '''

        log_print("user login")
        for session in sessions:
            try:
                session.login(pin)
                return session
            except:
                continue

        raise ValueError(
            "Can not login on sessions provided. Check Smart Card or PIN")

    @staticmethod
    def user_logout(session):
        ''' 
            User logout from a `session`

            Params:
                session: smart card session
        '''

        log_print("user logout")
        session.logout()

    @staticmethod
    def fetch_certificate(session):
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

    @staticmethod
    def get_certificate_value(session, certificate):
        ''' 
            Return the value of `certificate`

            Params:
                session: smart card session
                certificate: smart card certificate
        '''

        log_print("fetching certificate value")
        try:
            certificate_value = session.getAttributeValue(
                certificate, [LowLevel.CKA_VALUE])[0]
        except:
            raise

        dbg_print("certificate value", binascii.hexlify(
            bytes(certificate_value)))
        return bytes(certificate_value)

    @staticmethod
    def get_certificate_issuer(session, certificate):
        ''' 
            Return the issuer of `certificate`

            Params:
                session: smart card session
                certificate: smart card certificate
        '''

        log_print("fetching certificate issuer")
        try:
            certificate_issuer = session.getAttributeValue(
                certificate, [LowLevel.CKA_ISSUER])[0]
        except:
            raise
            
        dbg_print("certificate issuer", binascii.hexlify(
            bytes(certificate_issuer)))
        return bytes(certificate_issuer)

    @staticmethod
    def get_certificate_serial_number(session, certificate):
        ''' 
            Return the serial number of `certificate`

            Params:
                session: smart card session
                certificate: smart card certificate
        '''

        log_print("fetching certificate serial number")
        try:
            serial_number = session.getAttributeValue(
                certificate, [LowLevel.CKA_SERIAL_NUMBER])[0]
        except:
            raise
            
        int_serial_number = int.from_bytes(
            serial_number, byteorder='big', signed=True)
        dbg_print("certificate serial number", str(int_serial_number))
        return int_serial_number

    @staticmethod
    def fetch_private_key(session, certificate):
        ''' 
            Return smart card private key reference

            Params:
                session: smart card session
                certificate: certificate connected to the key
        '''

        log_print("fetching privKey")
        try:
            # getting the certificate id
            identifier = session.getAttributeValue(
                certificate, [LowLevel.CKA_ID])[0]
            # same as the key id
            privKey = session.findObjects([
                (LowLevel.CKA_CLASS, LowLevel.CKO_PRIVATE_KEY),
                (LowLevel.CKA_ID, identifier)])[0]
        except:
            raise
        # if you don't print privKey you get a sign general error -.-
        print(privKey, file=open(devnull, "w"))  # to avoid general error
        dbg_print("private key", privKey)
        return privKey

    @staticmethod
    def fetch_public_key(session, certificate):
        ''' 
            Return smart card public key reference

            Params:
                session: smart card session
                certificate: certificate connected to the key
        '''

        log_print("fetching pubKey")
        try:
            # getting the certificate id
            identifier = session.getAttributeValue(
                certificate, [LowLevel.CKA_ID])[0]
            # same as the key id
            pubKey = session.findObjects([
                (LowLevel.CKA_CLASS, LowLevel.CKO_PUBLIC_KEY),
                (LowLevel.CKA_ID, identifier)])[0]
        except:
            raise
        dbg_print("public key", pubKey)
        return pubKey

    @staticmethod
    def digest(session, content):
        ''' 
            Return `content` hash

            Params:
                session: smart card session
                content: content to hash
        '''

        log_print("hashing content")
        try:
            digest = session.digest(content, Mechanism(LowLevel.CKM_SHA256))
        except:
            raise
            
        dbg_print("digest", binascii.hexlify(bytes(digest)))
        return bytes(digest)

    @staticmethod
    def signature(session, privKey, content):
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
        try:
            signature = session.sign(privKey, content, Mechanism(
                LowLevel.CKM_SHA256_RSA_PKCS, None))
        except:
            raise
            
        dbg_print("signature", binascii.hexlify(bytes(signature)))
        return bytes(signature)
