/*
// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#include "sslhelper.h"

#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "s_helpers.h"

/// Extract R and S values from signature, stripping off 0x00 MSB if it exists,
/// resulting in fixed sizes for R and S
int ExtractRs(const unsigned char *sig, const int sigLen, unsigned char **r,
              unsigned char **s, int *len)
{
    int ret = 1;
    int i, j;
    uint8_t skipR = 0;
    uint8_t skipS = 0;
    // currently we will extract up to 384 curve, expand later
    if (sigLen < 70 || sig == NULL)
    {
        // invalid sig length
        fprintf(stderr, "%sSignature length is too short to be correct.\n",
                getErr());
        ret = 0;
    }
    // figure out point length and if we need to skip a byte
    if (ret)
    {
        if (sig[3] == 0x20 || sig[3] == 0x21)
        {
            if (sig[3] == 0x21)
            {
                skipR = 0x01;
            }
            if (sig[3 + sig[3] + 2] == 0x21)
            {
                skipS = 0x01;
            }
            *len = 0x20;
        }
        else if (sig[3] == 0x30 || sig[3] == 0x31)
        {
            if (sig[3] == 0x31)
            {
                skipR = 0x01;
            }
            if (sig[3 + sig[3] + 2] == 0x31)
            {
                skipS = 0x01;
            }
            *len = 0x30;
        }
        else if (sig[3] == 0x41 || sig[3] == 0x42)
        {
            // TODO: Not sure how to handle 512 curves.
            if (sig[3] == 0x42)
            {
                skipR = 0x01;
            }
            if (sig[3 + sig[3]] == 0x42)
            {
                skipS = 0x01;
            }
            *len = 0x41;
        }
        else
        {
            fprintf(stderr, "%sFailed to decode DER header.\n", getErr());
            ret = 0;
        }
    }
    // make sure we can do math correctly
    if (((*len) * 2) + skipR + skipS + 6 != sigLen)
    {
        fprintf(stderr,
                "%sDecoded length from DER does not equal signature length.\n",
                getErr());
        fprintf(stderr, "%ssigLen = %d\n", getErr(), sigLen);
        fprintf(stderr, "%slen = %d\n", getErr(), *len);
        fprintf(stderr, "%sskipR = %d\n", getErr(), skipR);
        fprintf(stderr, "%sskipS = %d\n", getErr(), skipS);
        fprintf(stderr, "%sDER Encoded Signature:\n", getErr());
        hexDump(sig, sigLen, "  ", stderr, getErr());
        ret = 0;
    }
    else
    {
        *r = malloc(*len * sizeof(unsigned char));
        for (i = 4 + skipR, j = 0; j < *len && i < sigLen; ++i, ++j)
        {
            (*r)[j] = sig[i];
        }
        *s = malloc(*len * sizeof(unsigned char));
        for (i += 2 + skipS, j = 0; j < *len && i < sigLen; ++i, ++j)
        {
            (*s)[j] = sig[i];
        }
    }
    return ret;
}

/// Re-encodes R/S coordinates with stripped 0x00
int DerEncodeRs(const unsigned char *r, const unsigned char *s,
                const int pointLen, unsigned char **sig, int *sigLen)
{
    int ret = 1;
    int i = 0;
    int j;
    int padR = 0;
    int padS = 0;
    if (r == NULL || s == NULL || sig == NULL)
    {
        fprintf(stderr, "%sR, S or sig is NULL\n", getErr());
        ret = 0;
    }
    if (ret)
    {
        // if most significant bit is 1, pad 0x00
        if (r[0] & 0x80)
        {
            padR = 1;
        }
        if (s[0] & 0x80)
        {
            padS = 1;
        }
        *sigLen = pointLen * 2 + padR + padS + 6;
        *sig = malloc(*sigLen);
        (*sig)[i++] = 0x30;
        (*sig)[i++] = *sigLen - 2;
        (*sig)[i++] = 0x02;
        (*sig)[i++] = pointLen + padR;
        if (padR)
        {
            (*sig)[i++] = 0x00;
        }
        for (j = 0; j < pointLen; ++j, ++i)
        {
            (*sig)[i] = r[j];
        }
        (*sig)[i++] = 0x02;
        (*sig)[i++] = pointLen + padS;
        if (padS)
        {
            (*sig)[i++] = 0x00;
        }
        for (j = 0; j < pointLen; ++j, ++i)
        {
            (*sig)[i] = s[j];
        }
    }

    return ret;
}

int ExtractQxQyFromPubkey(const char *file, unsigned char **qx,
                          unsigned char **qy, int *len)
{
    int ret = 1;
    int i, j;
    unsigned char *pub;
    int publen;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    EC_KEY *eckey = NULL;
#else
    EVP_PKEY *eckey = NULL;
#endif
    // check for any NULLs
    if (file == NULL)
    {
        fprintf(stderr, "%sFile is NULL.\n", getErr());
        ret = 0;
    }
    if (ret)
    {
        BIO *in = BIO_new_file(file, "r");
        if (in == NULL)
        {
            fprintf(stderr, "%sFailed to read eckey %s.\n", getErr(), file);
            ret = 0;
        }
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
        if (ret)
        {
            eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
        }
        if (eckey == NULL && ret)
        {
            fprintf(stderr, "%sFailed to read eckey %s.\n", getErr(), file);
            ret = 0;
        }
        if (ret)
        {
            publen =
                EC_KEY_key2buf(eckey, EC_KEY_get_conv_form(eckey), &pub, NULL);
#else
        if (ret)
        {
            eckey = PEM_read_bio_PUBKEY(in, NULL, NULL, NULL);
        }
        if (eckey == NULL && ret)
        {
            fprintf(stderr, "%sFailed to read eckey %s.\n", getErr(), file);
            ret = 0;
        }
        if (ret)
        {
            publen =
                EVP_PKEY_get1_encoded_public_key(eckey, &pub);
#endif
            if (pub[0] != 0x04)
            {
                // key is compressed, we don't support this
                fprintf(stderr,
                        "%sKey is in compressed format. This is currently not "
                        "supported.\n",
                        getErr());
                ret = 0;
            }
            *len = (publen - 1) / 2;
            // SET QX
            (*qx) = malloc((*len + 1) * sizeof(unsigned char));
            for (i = 1, j = 0; j < *len; ++i, ++j)
            {
                (*qx)[j] = pub[i];
            }
            (*qy) = malloc((*len + 1) * sizeof(unsigned char));
            for (i = *len + 1, j = 0; j < *len; ++i, ++j)
            {
                (*qy)[j] = pub[i];
            }
        }
    }
    return ret;
}

int HashBuffer(const uint8_t *buffer, const int bufSize, const HashAlg hashAlg,
               unsigned char **hash, int *size)
{
    int ret = 1;
    EVP_MD_CTX *mctx = NULL;
    const EVP_MD *md = NULL;
    // check for any NULLs
    if (buffer == NULL || hash == NULL || size == NULL)
    {
        fprintf(stderr, "%sBuffer, hash or size is NULL.\n", getErr());
        ret = 0;
    }
    if (ret != 0)
    {
        if (hashAlg == Sha256)
        {
            *size = SHA256_DIGEST_LENGTH;
            md = EVP_sha256();
        }
        else if (hashAlg == Sha384)
        {
            *size = SHA384_DIGEST_LENGTH;
            md = EVP_sha384();
        }
        else if (hashAlg == Sha512)
        {
            *size = SHA512_DIGEST_LENGTH;
            md = EVP_sha512();
        }

        *hash = (unsigned char *)malloc(*size);
        mctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mctx, md, NULL);

        ret = EVP_DigestUpdate(mctx, buffer, bufSize);
        // Final frees mctx memory
        if (ret != 0 &&
            EVP_DigestFinal_ex(mctx, *hash, (unsigned int *)size) <= 0)
        {
            fprintf(stderr, "%sFailed to generate hash.\n", getErr());
            ret = 0;
        }

        EVP_MD_CTX_free(mctx);
    }

    return ret;
}

int HashFilePointer(FILE *fp, const HashAlg hashAlg, unsigned char **hash,
                    int *size)
{
    int ret = 1;
    EVP_MD_CTX *mctx = NULL;
    const EVP_MD *md = NULL;
    // check for any NULLs
    if (fp == NULL || hash == NULL || size == NULL)
    {
        fprintf(stderr, "%sFile, hash, or size is NULL.\n", getErr());
        ret = 0;
    }
    if (ret != 0)
    {
        if (hashAlg == Sha256)
        {
            *size = SHA256_DIGEST_LENGTH;
            md = EVP_sha256();
        }
        else if (hashAlg == Sha384)
        {
            *size = SHA384_DIGEST_LENGTH;
            md = EVP_sha384();
        }
        else if (hashAlg == Sha512)
        {
            *size = SHA512_DIGEST_LENGTH;
            md = EVP_sha512();
        }

        *hash = (unsigned char *)malloc(*size);
        mctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mctx, md, NULL);

        char *hashBlock[HASH_BLOCK_SIZE];
        int blockActual = 0;
        // Handle Files
        blockActual = fread(hashBlock, 1, HASH_BLOCK_SIZE, fp);
        while (ret != 0 && blockActual == HASH_BLOCK_SIZE)
        {
            ret = EVP_DigestUpdate(mctx, hashBlock, HASH_BLOCK_SIZE);
            blockActual = fread(hashBlock, 1, HASH_BLOCK_SIZE, fp);
        }

        // Final block update will be partial
        // What happens if 0 gets passed into blockActual?
        if (ret != 0 && EVP_DigestUpdate(mctx, hashBlock, blockActual) <= 0)
        {
            fprintf(stderr, "%sFailed to generate hash.\n", getErr());
            ret = 0;
        }

        // Final frees mctx memory
        if (ret != 0 &&
            EVP_DigestFinal_ex(mctx, *hash, (unsigned int *)size) <= 0)
        {
            fprintf(stderr, "%sFailed to generate hash.\n", getErr());
            ret = 0;
        }

        EVP_MD_CTX_free(mctx);
    }
    return ret;
}

int HashFile(const char *file, const HashAlg hashAlg, unsigned char **hash,
             int *size)
{
    int ret = 1;
    EVP_MD_CTX *mctx = NULL;
    const EVP_MD *md = NULL;
    // check for any NULLs
    if (file == NULL || hash == NULL || size == NULL)
    {
        fprintf(stderr, "%sFile, hash, or size is NULL.\n", getErr());
        ret = 0;
    }
    if (ret != 0)
    {
        if (hashAlg == Sha256)
        {
            *size = SHA256_DIGEST_LENGTH;
            md = EVP_sha256();
        }
        else if (hashAlg == Sha384)
        {
            *size = SHA384_DIGEST_LENGTH;
            md = EVP_sha384();
        }
        else if (hashAlg == Sha512)
        {
            *size = SHA512_DIGEST_LENGTH;
            md = EVP_sha512();
        }

        *hash = (unsigned char *)malloc(*size);
        mctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mctx, md, NULL);

        char *hashBlock[HASH_BLOCK_SIZE];
        int blockActual = 0;
        // Handle Files
        FILE *fp = NULL;
        ret = openFile(&fp, file, "r");
        if (ret != 0)
        {
            blockActual = fread(hashBlock, 1, HASH_BLOCK_SIZE, fp);
        }
        else
        {
            fprintf(stderr, "%sFailed to open file %s.\n", getErr(), file);
        }
        while (ret != 0 && blockActual == HASH_BLOCK_SIZE)
        {
            ret = EVP_DigestUpdate(mctx, hashBlock, HASH_BLOCK_SIZE);
            blockActual = fread(hashBlock, 1, HASH_BLOCK_SIZE, fp);
        }

        // Final block update will be partial
        // What happens if 0 gets passed into blockActual?
        if (ret != 0 && EVP_DigestUpdate(mctx, hashBlock, blockActual) <= 0)
        {
            fprintf(stderr, "%sFailed to generate hash.\n", getErr());
            ret = 0;
        }

        if (fp != NULL)
        {
            ret = !(fclose(fp));
            fp = NULL;
        }

        // Final frees mctx memory
        if (ret != 0 &&
            EVP_DigestFinal_ex(mctx, *hash, (unsigned int *)size) <= 0)
        {
            fprintf(stderr, "%sFailed to generate hash.\n", getErr());
            ret = 0;
        }

        EVP_MD_CTX_free(mctx);
    }

    return ret;
}

int SignData(const char *certFile, const SigAlg sigAlg,
             const unsigned char *data, const HashAlg hashAlg,
             unsigned char **sig, int *sigSize) //, Logging *log=NULL)
{
    int ret = 1;               // Holds return values
    BIO *pkeyBio = NULL;       // For reading in private key
    EVP_PKEY *pkey = NULL;     // Private key EVP
    EVP_PKEY_CTX *pctx = NULL; // Private key EVP context
    const EVP_MD *md = NULL;   // Hash alg context must be specified for signing
    size_t mdLen = 0;          // Length of message digest
    size_t siglen;             // Length of signature

    if (certFile == NULL || data == NULL || sig == NULL || sigSize == NULL)
    {
        fprintf(stderr, "%sCert file, data, sig, or sig size is NULL.\n",
                getErr());
        ret = 0;
    }
    if (ret != 0)
    {
        // Read in the private key
        pkeyBio = BIO_new_file(certFile, "r");
        if (!pkeyBio)
        {
            fprintf(stderr, "%sFailed to read in certificate file %s.\n",
                    getErr(), certFile);
            ret = 0;
        }
        if (ret)
        {
            pkey = PEM_read_bio_PrivateKey(pkeyBio, NULL, NULL, NULL);
        }
        if (!pkey && ret)
        {
            fprintf(stderr, "%sFailed to read in certificate file %s.\n",
                    getErr(), certFile);
            ret = 0;
        }

        // Set the hash length (derived from hashAlg) and Md Context
        if (ret != 0)
        {
            if (hashAlg == Sha256)
            {
                mdLen = SHA256_DIGEST_LENGTH;
                md = EVP_sha256();
            }
            else if (hashAlg == Sha384)
            {
                mdLen = SHA384_DIGEST_LENGTH;
                md = EVP_sha384();
            }
            else if (hashAlg == Sha512)
            {
                mdLen = SHA512_DIGEST_LENGTH;
                md = EVP_sha512();
            }

            // Malloc and initialize the private key context
            pctx = EVP_PKEY_CTX_new(pkey, NULL);
            if (!pctx)
            {
                fprintf(stderr, "%sFailed to generate PKEY context.\n",
                        getErr());
                ret = 0;
            }
            if (ret != 0 && EVP_PKEY_sign_init(pctx) <= 0)
            {
                fprintf(stderr, "%sFailed to initialize signer.\n", getErr());
                ret = 0;
            }

            // Specify padding for RsaSsa/RsaPss
            if (ret != 0 && sigAlg == RsaSsa)
            {
                if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
                {
                    fprintf(stderr, "%sFailed to set PKCS padding.\n",
                            getErr());
                    ret = 0;
                }
            }
            else if (ret != 0 && sigAlg == RsaPss)
            {
                if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <=
                    0)
                {
                    fprintf(stderr, "%sFailed to set PSS padding.\n", getErr());
                    ret = 0;
                }
            }

            // Set the message digest type for PKEY context
            if (ret != 0 && EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0)
            {
                fprintf(stderr, "%sFailed to set the message digest.\n",
                        getErr());
                ret = 0;
            }

            // If sig is NULL, max sig length is returned for length (malloc
            // calculation)
            if (ret != 0 &&
                EVP_PKEY_sign(pctx, NULL, &siglen, data, mdLen) <= 0)
            {
                fprintf(stderr, "%sFailed to calculate signature length.\n",
                        getErr());
                ret = 0;
            }

            // Allocate sig
            if (ret != 0)
            {
                *sig = (unsigned char *)malloc(siglen);
            }

            if (ret != 0 && !sig)
            {
                ret = 0;
            }

            // Perform signing
            if (ret != 0 &&
                EVP_PKEY_sign(pctx, *sig, &siglen, data, mdLen) <= 0)
            {
                fprintf(stderr,
                        "%sFailed to perform signing operation with key %s.\n",
                        getErr(), certFile);
                ret = 0;
            }

            // Assign sigSize, I could make this size_t as an input
            if (ret != 0 && siglen < INT_MAX)
            {
                *sigSize = (int)siglen;
            }
        }

        // Clean up allocated stuff
        if (pctx != NULL)
        {
            EVP_PKEY_CTX_free(pctx);
        }
        if (pkey != NULL)
        {
            EVP_PKEY_free(pkey);
        }
        if (pkeyBio != NULL)
        {
            BIO_free(pkeyBio);
        }
    }

    return ret;
}

int VerifyData(const char *certFile, const SigAlg sigAlg,
               const unsigned char *data, const HashAlg hashAlg,
               const unsigned char *sig, const int sigSize,
               int *verified) //, Logging *log=NULL)
{
    int ret = 1;               // Holds the return value
    BIO *pkeyBio = NULL;       // For reading in private key
    EVP_PKEY *pkey = NULL;     // Private key EVP
    EVP_PKEY_CTX *pctx = NULL; // Private key EVP context
    const EVP_MD *md = NULL;   // Hash alg context must be specified for signing
    size_t mdLen = 0;          // Length of message digest
    size_t siglen;             // Length of signature

    // null check
    if (certFile == NULL || data == NULL || sig == NULL || verified == NULL)
    {
        fprintf(stderr, "%sCert file, data, sig, or verified flag is NULL.\n",
                getErr());
        ret = 0;
    }

    if (ret != 0)
    {
        *verified = 0;
        // Read in the public key
        pkeyBio = BIO_new_file(certFile, "r");
        if (pkeyBio == NULL)
        {
            fprintf(stderr, "%sFailed to read in key %s.\n", getErr(),
                    certFile);
            ret = 0;
        }
        if (ret)
        {
            pkey = PEM_read_bio_PUBKEY(pkeyBio, NULL, NULL, NULL);
        }
        if (!pkey && ret)
        {
            BIO_reset(pkeyBio);
            pkey = PEM_read_bio_PrivateKey(pkeyBio, NULL, NULL, NULL);
            if (!pkey)
            {
                fprintf(stderr, "%sFailed to read in key %s.\n", getErr(),
                        certFile);
                ret = 0;
            }
        }

        // Set the hash length (derived from hashAlg) and Md Context
        if (hashAlg == Sha256)
        {
            mdLen = SHA256_DIGEST_LENGTH;
            md = EVP_sha256();
        }
        else if (hashAlg == Sha384)
        {
            mdLen = SHA384_DIGEST_LENGTH;
            md = EVP_sha384();
        }
        else if (hashAlg == Sha512)
        {
            mdLen = SHA512_DIGEST_LENGTH;
            md = EVP_sha512();
        }

        // Malloc and initialize the private key context
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (ret != 0 && !pctx)
        {
            fprintf(stderr, "%sFailed to read create PKEY context.\n",
                    getErr());
            ret = 0;
        }
        if (ret != 0 && EVP_PKEY_verify_init(pctx) <= 0)
        {
            fprintf(stderr, "%sFailed to initialize verification engine.\n",
                    getErr());
            ret = 0;
        }

        // Specify padding for RsaSsa/RsaPss
        if (ret != 0 && sigAlg == RsaSsa)
        {
            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
            {
                fprintf(stderr, "%sFailed to set PKCS padding.\n", getErr());
                ret = 0;
            }
        }
        else if (ret != 0 && sigAlg == RsaPss)
        {
            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
            {
                fprintf(stderr, "%sFailed to set PSS padding.\n", getErr());
                ret = 0;
            }
        }

        // Set the message digest type for PKEY context
        if (ret != 0 && EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0)
        {
            fprintf(stderr, "%sFailed to set the message digest.\n", getErr());
            ret = 0;
        }

        siglen = (size_t)sigSize;
        if (ret != 0)
        {
            *verified = EVP_PKEY_verify(pctx, sig, siglen, data, mdLen);
        }

        if (pctx != NULL)
        {
            EVP_PKEY_CTX_free(pctx);
        }
        if (pkey != NULL)
        {
            EVP_PKEY_free(pkey);
        }
        if (pkeyBio != NULL)
        {
            BIO_free(pkeyBio);
        }
    }

    return ret;
}
