#ifndef _SSLHELPER_H_
#define _SSLHELPER_H_
#include <openssl/evp.h>

// TODO: Remove this once it gets upstreamed into OpenSSL
#define SM3_DIGEST_LENGTH 32

// Separated out from my SSLHelper library for ease of compiling.
// Make sure to upstream changes.
/*#ifdef _WIN32
#ifdef SSLHELPER_LIB_EXPORTS
#define SSLHELPER_LIB_API __declspec(dllexport)
#else
#define SSLHELPER_LIB_API __declspec(dllimport)
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif*/
#define HASH_BLOCK_SIZE 1024
// Supported Sig Algorithms - Sm2 is WIP
typedef enum { RsaSsa, RsaPss, EcDsa, Sm2 } SigAlg;
// Supported Hash Algorithms - Sm3 is WIP
typedef enum { Sha256, Sha384, Sha512, Sm3 } HashAlg;

/*#ifdef _WIN32
SSLHELPER_LIB_API
#endif*/
int ExtractRs(
/* IN  */ const unsigned char     *sig,
/* IN  */ const int               sigLen,
/* OUT */ unsigned char           **r,
/* OUT */ unsigned char           **s,
/* OUT */ int                     *len
);

/*#ifdef _WIN32
SSLHELPER_LIB_API
#endif*/
int DerEncodeRs(
    /* IN  */ const unsigned char     *r,
    /* IN  */ const unsigned char     *s,
    /* IN  */ const int               pointLen,
    /* OUT */ unsigned char           **sig,
    /* OUT */ int                     *sigLen
);

/*#ifdef _WIN32
SSLHELPER_LIB_API
#endif*/
int ExtractQxQyFromPubkey(
/* IN  */ const char        *file,
/* OUT */ unsigned char     **qx,
/* OUT */ unsigned char     **qy,
/* OUT */ int               *len
);

// Hash must be freed via caller
/*#ifdef _WIN32
SSLHELPER_LIB_API
#endif*/
int HashFilePointer(
    /* IN  */ FILE                *file,
    /* IN  */ const HashAlg     hashAlg,
    /* OUT */ unsigned char     **hash,
    /* OUT */ int               *size
);

// Hash must be freed via caller
/*#ifdef _WIN32
SSLHELPER_LIB_API
#endif*/
int HashFile(
/* IN  */ const char        *file, 
/* IN  */ const HashAlg     hashAlg,
/* OUT */ unsigned char     **hash,
/* OUT */ int               *size
);

// Hash must be freed via caller
/*#ifdef _WIN32
SSLHELPER_LIB_API
#endif*/
int HashBuffer(
    /* IN  */ const uint8_t     *buffer,
    /* IN  */ const int         bufSize,
    /* IN  */ const HashAlg     hashAlg,
    /* OUT */ unsigned char     **hash,
    /* OUT */ int               *size
);

// Sig must be freed via caller
/*#ifdef _WIN32
SSLHELPER_LIB_API
#endif*/
int SignData(
/* IN  */ const char        *certFile,
/* IN  */ const SigAlg      sigAlg,
/* IN  */ const unsigned char     *data,
/* IN  */ const HashAlg     hashAlg,
/* OUT */ unsigned char     **sig,
/* OUT */ int               *sigSize
);

/*#ifdef _WIN32
SSLHELPER_LIB_API
#endif*/
int VerifyData(
/* IN  */ const char        *certFile,
/* IN  */ const SigAlg      sigAlg,
/* IN  */ const unsigned char *data,
/* IN  */ const HashAlg     hashAlg,
/* IN  */ const unsigned char *sig,
/* IN  */ const int         sigSize,
/* OUT */ int               *verified // 0 - Failure, 1 - Success
);
#ifdef __cplusplus
}
#endif
#endif