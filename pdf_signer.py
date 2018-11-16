# *-* coding: utf-8 *-*
import hashlib
from datetime import datetime
from asn1crypto import cms, algos, core, tsp

from signature_util import SignatureUtils
from asn1crypto.x509 import Certificate
from PyKCS11 import Mechanism, LowLevel
from my_logger import MyLogger


def sign(datau, session, cert, cert_value, hashalgo, attrs=True, signed_value=None):
    if signed_value is None:
        signed_value = getattr(hashlib, hashalgo)(datau).digest()
    signed_time = datetime.now()

    x509 = Certificate.load(cert_value)
    certificates = []
    certificates.append(x509)

    cert_value_digest = bytes(session.digest(cert_value, Mechanism(LowLevel.CKM_SHA256)))
    MyLogger().my_logger().info('building signed attributes...')
    signer = {
        'version': 'v1',
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': x509.issuer,
                'serial_number': x509.serial_number,
            }),
        }),
        'digest_algorithm': algos.DigestAlgorithm({'algorithm': hashalgo}),
        'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'}),
        'signature': signed_value,
    }
    if attrs:
        signer['signed_attrs'] = [
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('content_type'),
                'values': ('data',),
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('message_digest'),
                'values': (signed_value,),
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('signing_time'),
                'values': (cms.Time({'utc_time': core.UTCTime(signed_time)}),)
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('1.2.840.113549.1.9.16.2.47'),
                'values': (tsp.SigningCertificateV2({
                    'certs': (tsp.ESSCertIDv2({
                        'hash_algorithm': algos.DigestAlgorithm({'algorithm': hashalgo, 'parameters': None}),
                        'cert_hash': cert_value_digest,
                    }),),
                }),)
            }),
        ]
    config = {
        'version': 'v1',
        'digest_algorithms': cms.DigestAlgorithms((
            algos.DigestAlgorithm({'algorithm': hashalgo}),
        )),
        'encap_content_info': {
            'content_type': 'data',
        },
        'certificates': certificates,
        # 'crls': [],
        'signer_infos': [
            signer,
        ],
    }
    datas = cms.ContentInfo({
        'content_type': cms.ContentType('signed_data'),
        'content': cms.SignedData(config),
    })
    if attrs:
        tosign = datas['content']['signer_infos'][0]['signed_attrs'].dump()
        tosign = b'\x31' + tosign[1:]
    else:
        tosign = datau

    MyLogger().my_logger().info('signed attributes ready')
    # fetching private key from smart card
    priv_key = SignatureUtils.fetch_private_key(session, cert)
    mechanism = Mechanism(LowLevel.CKM_SHA256_RSA_PKCS, None)
    MyLogger().my_logger().info('signing...')
    # signing bytes to be signed
    signature = session.sign(priv_key, tosign, mechanism)

    datas['content']['signer_infos'][0]['signature'] = bytes(signature)

    return datas.dump()
