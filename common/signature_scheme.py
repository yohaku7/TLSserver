from tls_object import TLSIntEnum
from enum import IntEnum


class SignatureScheme(TLSIntEnum, IntEnum):
    # refer:
    # https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
    rsa_pkcs1_sha1 = 0x0201
    ecdsa_sha1 = 0x0203

    rsa_pkcs1_sha256 = 0x0401
    ecdsa_secp256r1_sha256 = 0x0403
    # rsa_pkcs1_sha256_legacy = 0x0420

    rsa_pkcs1_sha384 = 0x0501
    ecdsa_secp384r1_sha384 = 0x0503
    # rsa_pkcs1_sha384_legacy = 0x0520

    rsa_pkcs1_sha512 = 0x0601
    ecdsa_secp521r1_sha512 = 0x0603
    # rsa_pkcs1_sha512_legacy = 0x0620

    # NOT RECOMMENDED
    eccsi_sha256 = 0x0704
    iso_ibs1 = 0x0705
    iso_ibs2 = 0x0706
    iso_chinese_ibs = 0x0707
    sm2sig_sm3 = 0x0708
    gostr34102012_256a = 0x0709
    gostr34102012_256b = 0x070a
    gostr34102012_256c = 0x070b
    gostr34102012_256d = 0x070c
    gostr34102012_512a = 0x070d
    gostr34102012_512b = 0x070e
    gostr34102012_512c = 0x070f

    rsa_pss_rsae_sha256 = 0x0804
    rsa_pss_rsae_sha384 = 0x0805
    rsa_pss_rsae_sha512 = 0x0806
    ed25519 = 0x0807
    ed448 = 0x0808
    rsa_pss_pss_sha256 = 0x0809
    rsa_pss_pss_sha384 = 0x080a
    rsa_pss_pss_sha512 = 0x080b

    # NOT RECOMMENDED
    ecdsa_brainpoolP256r1tls13_sha256 = 0x081a
    ecdsa_brainpoolP384r1tls13_sha384 = 0x081b
    ecdsa_brainpoolP512r1tls13_sha512 = 0x081c

    @classmethod
    def byte_length(cls) -> int:
        return 2
