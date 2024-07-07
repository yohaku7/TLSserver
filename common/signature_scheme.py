from enum import IntEnum


class SignatureScheme(IntEnum):
    # RSASSA-PKCS-v1_5
    rsa_pkcs1_sha256 = 0x0401
    rsa_pkcs1_sha384 = 0x0501
    rsa_pkcs1_sha512 = 0x0601

    # ECDSA
    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ecdsa_secp521r1_sha512 = 0x0603

    # RSASSA-PSS algo. with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804
    rsa_pss_rsae_sha384 = 0x0805
    rsa_pss_rsae_sha512 = 0x0806

    # EdDSA
    ed25519 = 0x0807
    ed448   = 0x0808

    # RSASSA-PSS algo. with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809
    rsa_pss_pss_sha384 = 0x080a
    rsa_pss_pss_sha512 = 0x080b

    # Legacy
    rsa_pkcs1_sha1 = 0x0201
    ecdsa_sha1 = 0x0203
    # 0xffff
