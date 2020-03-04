#ifndef _TCG_H_
#define _TCG_H_

#define TPM_ALG_ERROR 0x0000
#define TPM_ALG_RSA 0x0001
#define TPM_ALG_SHA 0x0004
#define TPM_ALG_SHA1 0x0004
#define TPM_ALG_HMAC 0x0005
#define TPM_ALG_AES 0x0006
#define TPM_ALG_MGF1 0x0007
#define TPM_ALG_KEYEDHASH 0x0008
#define TPM_ALG_XOR 0x000A
#define TPM_ALG_SHA256 0x000B
#define TPM_ALG_SHA384 0x000C
#define TPM_ALG_SHA512 0x000D
#define TPM_ALG_NULL 0x0010
#define TPM_ALG_SM3_256 0x0012
#define TPM_ALG_SM4 0x0013
#define TPM_ALG_RSASSA 0x0014
#define TPM_ALG_RSAES 0x0015
#define TPM_ALG_RSAPSS 0x0016
#define TPM_ALG_OAEP 0x0017
#define TPM_ALG_ECDSA 0x0018
#define TPM_ALG_ECDH 0x0019
#define TPM_ALG_ECDAA 0x001A
#define TPM_ALG_SM2 0x001B
#define TPM_ALG_ECSCHNORR 0x001C
#define TPM_ALG_ECMQV 0x001D
#define TPM_ALG_KDF1_SP800_56A 0x0020
#define TPM_ALG_KDF2 0x0021
#define TPM_ALG_KDF1_SP800_108 0x0022
#define TPM_ALG_ECC 0x0023
#define TPM_ALG_SYMCIPHER 0x0025
#define TPM_ALG_CAMELLIA 0x0026
#define TPM_ALG_CTR 0x0040
#define TPM_ALG_OFB 0x0041
#define TPM_ALG_CBC 0x0042
#define TPM_ALG_CFB 0x0043
#define TPM_ALG_ECB 0x0044

#define TPM_ECC_NONE 0x0000
#define TPM_ECC_NIST_P192 0x0001
#define TPM_ECC_NIST_P224 0x0002
#define TPM_ECC_NIST_P256 0x0003
#define TPM_ECC_NIST_P384 0x0004
#define TPM_ECC_NIST_P521 0x0005
#define TPM_ECC_BN_P256 0x0010
#define TPM_ECC_BN_P638 0x0011
#define TPM_ECC_SM2_P256 0x0020

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE 64
#define SHA1_DER_SIZE 15
#define SHA1_DER                                                               \
    {                                                                          \
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A,      \
            0x05, 0x00, 0x04, 0x14                                             \
    }

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64
#define SHA256_DER_SIZE 19
#define SHA256_DER                                                             \
    {                                                                          \
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,      \
            0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20                     \
    }

#define SHA384_DIGEST_SIZE 48
#define SHA384_BLOCK_SIZE 128
#define SHA384_DER_SIZE 19
#define SHA384_DER                                                             \
    {                                                                          \
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,      \
            0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30                     \
    }

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE 128
#define SHA512_DER_SIZE 19
#define SHA512_DER                                                             \
    {                                                                          \
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,      \
            0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40                     \
    }

#define SM3_256_DIGEST_SIZE 32
#define SM3_256_BLOCK_SIZE 64
#define SM3_256_DER_SIZE 18
#define SM3_256_DER                                                            \
    {                                                                          \
        0x30, 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0x81, 0x45,      \
            0x01, 0x83, 0x11, 0x05, 0x00, 0x04, 0x20                           \
    }

#endif
