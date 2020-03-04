#include "blocksign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "blocks.h"
#include "cpld.h"
#include "log.h"
#include "s_helpers.h"
#include "sslhelper.h"
#include "tcg.h"
HashAlg getHashAlgFromTcg(uint16_t nibble)
{
    HashAlg ret = Sha256;
    switch (nibble)
    {
        case TPM_ALG_SHA384:
            ret = Sha384;
            break;
        case TPM_ALG_SHA512:
            ret = Sha512;
            break;
    }
    return ret;
}
const char *getHashStringFromTcg(uint16_t nibble)
{
    const char *ret = HASH_SHA256_STR;
    switch (nibble)
    {
        case TPM_ALG_SHA384:
            ret = HASH_SHA384_STR;
            break;
        case TPM_ALG_SHA512:
            ret = HASH_SHA512_STR;
            break;
    }
    return ret;
}

int zeroCheckSig(const unsigned char *r, const unsigned char *s, int size)
{
    int i;
    int ret = 1;
    // Zero check for signature.
    for (i = 0; r[i] == 0x00 && i < size; ++i)
        ;
    if (i == size)
    {
        fprintf(stderr,
                "%sSig(r) is all zeros (0x00). An error occurred while "
                "generating signature.\n",
                getErr());
        ret = 0;
    }
    for (i = 0; s[i] == 0x00 && i < size; ++i)
        ;
    if (i == size)
    {
        fprintf(stderr,
                "%sSig(s) is all zeros (0x00). An error occurred while "
                "generating signature.\n",
                getErr());
        ret = 0;
    }
    return ret;
}

int doExternalSign(const unsigned char *dataRaw, const int rawLen,
                   const unsigned char *hash, const int hashLen,
                   const char *filename, unsigned char **r, unsigned char **s,
                   int *externalLength, uint8_t verbose)
{
    unsigned char readBuffer[SIG_READ_BUFFER];
    int ret = 1;
    FILE *fp = NULL;
    int fileWriteChunk = 0;
    int fileReadChunk = 0;
    if (verbose)
    {
        printf("%s    Beginning external signing operation.\n", getNfo());
        printf("%s    Writing hash out to %s\n", getNfo(), FILE_DATA_HASH);
    }
    ret = openFile(&fp, FILE_DATA_HASH, "w");
    if (ret)
    {
        fileWriteChunk = fwrite(hash, sizeof(unsigned char), hashLen, fp);
        if (fileWriteChunk != hashLen)
        {
            fprintf(stderr, "%sFailed to write bytes out to file.\n", getErr());
            ret = 0;
        }
        else
        {
            ret = !(fclose(fp));
            fp = NULL;
        }
    }
    else
    {
        fprintf(stderr, "%sFailed to open file for writing.\n", getErr());
    }
    if (verbose)
    {
        printf("%s    Writing raw data out to %s\n", getNfo(), FILE_DATA_RAW);
    }
    ret = openFile(&fp, FILE_DATA_RAW, "w");
    if (ret)
    {
        fileWriteChunk = fwrite(dataRaw, sizeof(unsigned char), rawLen, fp);
        if (fileWriteChunk != rawLen)
        {
            ret = 0;
        }
        else
        {
            ret = !(fclose(fp));
            fp = NULL;
        }
        if (ret)
        {
            if (verbose)
            {
                printf("%s    Calling %s\n", getNfo(), filename);
            }

            ret = !(system(filename)); // 0 is good, so invert
            if (ret)
            {
                if (verbose)
                {
                    printf("%s    Reading in and parsing %s\n", getNfo(),
                           FILE_SIG_EXPECT);
                }
                ret = openFile(&fp, FILE_SIG_EXPECT, "r");
                if (ret)
                {
                    fileReadChunk = fread(readBuffer, 1, SIG_READ_BUFFER, fp);
                    if (fileReadChunk > 0)
                    {
                        ret = ExtractRs(readBuffer, fileReadChunk, r, s,
                                        externalLength);
                        if (!ret)
                        {
                            fprintf(stderr,
                                    "%sFailed to extract r/s from signature\n",
                                    getErr());
                        }
                    }
                    else
                    {
                        fprintf(stderr, "%sFailed to read anything from %s",
                                getErr(), FILE_SIG_EXPECT);
                        ret = 0;
                    }
                }
                else
                {
                    fprintf(stderr, "%sFailed to open %s.", getErr(),
                            FILE_SIG_EXPECT);
                }
            }
            else
            {
                fprintf(stderr, "%sFailed to call out to %s.\n", getErr(),
                        filename);
            }
        }
    }
    else
    {
        fprintf(stderr, "%sFailed to open file for writing\n", getErr());
    }
    if (fp != NULL)
    {
        ret = !(fclose(fp));
        fp = NULL;
    }
    return ret;
}

int parseBlocks(ARGUMENTS *args)
{
    int i;
    int ret = 1;
    FILE *fp;
    int readChunkSize = 0;
    BLOCK_0 b0;
    BLOCK_1 b1;

    // verify vars
    int calcSize = 0;
    void *buff = NULL;
    unsigned char *hash = NULL;
    int hashLen = 0;
    unsigned char *sig = NULL;
    int sigLen = 0;
    int verified = 0;

    ret = openFile(&fp, args->inputBinary, "r");
    if (ret)
    {
        readChunkSize = fread(&b0, 1, sizeof(b0), fp);
        if (readChunkSize != sizeof(b0))
        {
            ret = 0;
            fprintf(stderr, "%sNot enough space to read in block 0\n",
                    getErr());
        }
        else
        {
            // begin readin of block 1
            readChunkSize = fread(&(b1.magic), 1, sizeof(b1.magic), fp);
            if (readChunkSize != sizeof(b1.magic))
            {
                ret = 0;
            }
            if (ret)
            {
                readChunkSize =
                    fread(&(b1.reserved1), 1, sizeof(b1.reserved1), fp);
                if (readChunkSize != sizeof(b1.reserved1))
                {
                    ret = 0;
                }
                if (ret)
                {
                    readChunkSize =
                        fread(&(b1.root_key), 1, sizeof(b1.root_key), fp);
                    if (readChunkSize != sizeof(b1.root_key))
                    {
                        ret = 0;
                    }
                    if (ret)
                    {
                        if (!(b0.pc_type & CANCELLATION_BIT))
                        {
                            readChunkSize =
                                fread(&(b1.cs_key), 1, sizeof(b1.cs_key), fp);
                            if (readChunkSize != sizeof(b1.cs_key))
                            {
                                ret = 0;
                            }
                        }
                        if (ret)
                        {
                            readChunkSize = fread(&(b1.block0_sig), 1,
                                                  sizeof(b1.block0_sig), fp);
                            if (readChunkSize != sizeof(b1.block0_sig))
                            {
                                ret = 0;
                            }
                        }
                    }
                }
            }

            if (!ret)
            {
                fprintf(stderr, "%sNot enough space to read in block 1\n",
                        getErr());
            }
            else
            {
                unsigned long pos;
                fflush(fp);
                // position now holds the start of PC
                pos = ftell(fp);
                if (args->blockpad != UINT32_MAX)
                {
                    if (args->blockpad > pos)
                    {
                        fseek(fp, 0, SEEK_END);
                        if (args->blockpad > (uint32_t)ftell(fp))
                        {
                            fprintf(stderr,
                                    "%sConfig file block pad size (%d) is "
                                    "greater than file length (%ld)\n",
                                    getErr(), args->blockpad, ftell(fp));
                        }
                        else
                        {
                            pos = args->blockpad;
                        }
                    }
                    else
                    {
                        fprintf(stderr,
                                "%sConfig file block pad size (%d) is smaller "
                                "than the actual block size (%ld)\n",
                                getErr(), args->blockpad, pos);
                    }
                }
                fseek(fp, pos, SEEK_SET);

                // print it all out
                printf("%sBlock 0 Magic:           0x%08X\n", getNfo(),
                       b0.magic);
                printf("%sBlock 0 PC Length:       %d\n", getNfo(),
                       b0.pc_length);
                printf("%sBlock 0 PC Type:         %d\n", getNfo(),
                       b0.pc_type % CANCELLATION_BIT);
                printf("%s  Cancellation bit:      %d\n", getNfo(),
                       (b0.pc_type & CANCELLATION_BIT) / CANCELLATION_BIT);
                printf("%sBlock 0 Reserved(1):\n", getNfo());
                hexDump(b0.reserved1, 4, "  ", stdout, getNfo());
                printf("%s\n", getNfo());
                printf("%sBlock 0 PC SHA256:\n", getNfo());
                hexDump(b0.sha256, 32, "  ", stdout, getNfo());
                printf("%s\n", getNfo());

                // Calculate hash sha256
                HashFilePointer(fp, Sha256, &hash, &hashLen);
                printf("%sPC Calculated SHA256:\n", getNfo());
                hexDump(hash, hashLen, "  ", stdout, getNfo());
                printf("%s\n", getNfo());
                fseek(fp, pos, SEEK_SET);
                for (i = 0; i < 32 && i < hashLen; ++i)
                {
                    if (hash[i] != b0.sha256[i])
                    {
                        fprintf(stderr,
                                "%s%s%s  *** Block 0 SHA256 does not match "
                                "calculated value ***%s\n",
                                getErr(), setAttribute(Bold), setAttribute(Red),
                                setAttribute(Clear));
                        i = 255;
                    }
                }

                if (i == hashLen)
                {
                    printf("%s%s%s*** Block 0 SHA256 matches calculated value "
                           "***%s\n",
                           getNfo(), setAttribute(Bold), setAttribute(Green),
                           setAttribute(Clear));
                }
                printf("%s\n", getNfo());
                if (hash != NULL)
                {
                    free(hash);
                    hash = NULL;
                }

                printf("%sBlock 0 PC SHA384:\n", getNfo());
                hexDump(b0.sha384, 48, "  ", stdout, getNfo());
                printf("%s\n", getNfo());
                // Calculate hash sha384
                HashFilePointer(fp, Sha384, &hash, &hashLen);
                printf("%sPC Calculated SHA384:\n", getNfo());
                hexDump(hash, hashLen, "  ", stdout, getNfo());
                printf("%s\n", getNfo());
                for (i = 0; i < 48 && i < hashLen; ++i)
                {
                    if (hash[i] != b0.sha384[i])
                    {
                        fprintf(stderr,
                                "%s%s%s  *** Block 0 SHA384 does not match "
                                "calculated value ***%s\n",
                                getErr(), setAttribute(Bold), setAttribute(Red),
                                setAttribute(Clear));
                        i = 255;
                    }
                }
                if (i == hashLen)
                {
                    printf("%s%s%s*** Block 0 SHA384 matches calculated value "
                           "***%s\n",
                           getNfo(), setAttribute(Bold), setAttribute(Green),
                           setAttribute(Clear));
                }
                printf("%s\n", getNfo());
                if (hash != NULL)
                {
                    free(hash);
                    hash = NULL;
                }
                printf("%sBlock 0 Reserved(2):\n", getNfo());
                hexDump(b0.reserved2, 32, "  ", stdout, getNfo());
                printf("%s\n", getNfo());
                printf("%sBlock 1 Magic:           0x%08X\n", getNfo(),
                       b1.magic);
                printf("%sBlock 1 Reserved(1):\n", getNfo());
                hexDump(b1.reserved1, 12, "  ", stdout, getNfo());
                printf("%s\n", getNfo());
                printf("%s  Root Key Magic:        0x%08X\n", getNfo(),
                       b1.root_key.magic);
                printf("%s  Root Key Curve Magic:  0x%08X\n", getNfo(),
                       b1.root_key.curve_magic);
                printf("%s  Root Key Permissions:  %d\n", getNfo(),
                       b1.root_key.permissions);
                printf("%s  Root Key Key ID:       %d\n", getNfo(),
                       b1.root_key.keyid);
                printf("%s  Root Key Public (Qx):\n", getNfo());
                hexDump(b1.root_key.pubkey_x, 48, "    ", stdout, getNfo());
                printf("%s\n", getNfo());
                printf("%s  Root Key Public (Qy):\n", getNfo());
                hexDump(b1.root_key.pubkey_y, 48, "    ", stdout, getNfo());
                printf("%s\n", getNfo());
                printf("%s  Root Key Reserved1:\n", getNfo());
                hexDump(b1.root_key.reserved1, 20, "    ", stdout, getNfo());
                printf("%s\n", getNfo());
                if (!(b0.pc_type & CANCELLATION_BIT))
                {
                    printf("%s  CS Key Magic:          0x%08X\n", getNfo(),
                           b1.cs_key.magic);
                    printf("%s  CS Key Curve Magic:    0x%08X\n", getNfo(),
                           b1.cs_key.curve_magic);
                    printf("%s  CS Key Permissions:    %d\n", getNfo(),
                           b1.cs_key.permissions);
                    printf("%s  CS Key Key ID:    %d\n", getNfo(),
                           b1.cs_key.keyid);
                    printf("%s  CS Key Public (Qx):\n", getNfo());
                    hexDump(b1.cs_key.pubkey_x, EC_POINT_MAX, "    ", stdout,
                            getNfo());
                    printf("%s\n", getNfo());
                    printf("%s  CS Key Public (Qy):\n", getNfo());
                    hexDump(b1.cs_key.pubkey_y, EC_POINT_MAX, "    ", stdout,
                            getNfo());
                    printf("%s\n", getNfo());
                    printf("%s  CS Key Reserved1:\n", getNfo());
                    hexDump(b1.cs_key.reserved1, 20, "    ", stdout, getNfo());
                    printf("%s\n", getNfo());
                    printf("%s  CS KEY Sig Magic:      0x%08X\n", getNfo(),
                           b1.cs_key.sig_magic);
                    printf("%s  CS KEY Sig (r):\n", getNfo());
                    hexDump(b1.cs_key.sig_r, EC_POINT_MAX, "    ", stdout,
                            getNfo());
                    printf("%s\n", getNfo());
                    printf("%s  CS KEY Sig (s):\n", getNfo());
                    hexDump(b1.cs_key.sig_s, EC_POINT_MAX, "    ", stdout,
                            getNfo());
                    printf("%s\n", getNfo());

                    // If params have been loaded, attempt to verify signatures
                    if (args->b1_args.root_key.pubkey != NULL &&
                        args->b1_args.cskey.hashalg != UINT16_MAX)
                    {
                        printf("%s  CS KEY Signature Verification\n", getNfo());
                        calcSize = sizeof(b1.cs_key.curve_magic) +
                                   sizeof(b1.cs_key.permissions) +
                                   sizeof(b1.cs_key.keyid) +
                                   sizeof(b1.cs_key.pubkey_x) +
                                   sizeof(b1.cs_key.pubkey_y) +
                                   sizeof(b1.cs_key.reserved1);
                        buff = &(b1.cs_key.curve_magic);
                        ret = HashBuffer(
                            buff, calcSize,
                            getHashAlgFromTcg(args->b1_args.cskey.hashalg),
                            &hash, &hashLen);
                        if (ret)
                        {
                            printf("%s  CS KEY contents %s hash dump:\n",
                                   getNfo(),
                                   getHashStringFromTcg(
                                       args->b1_args.cskey.hashalg));
                            hexDump(hash, hashLen, "    ", stdout, getNfo());
                            printf("%s\n", getNfo());
                            // do size calculation if 32-48 are 0x00, then we
                            // assume 32
                            int pointLen = EC_POINT_256;
                            for (i = EC_POINT_256; i < EC_POINT_384; ++i)
                            {
                                if (b1.cs_key.sig_r[i] != 0x00)
                                {
                                    pointLen = EC_POINT_384;
                                    i = EC_POINT_384; // exit loop
                                }
                            }

                            ret = DerEncodeRs(b1.cs_key.sig_r, b1.cs_key.sig_s,
                                              pointLen, &sig, &sigLen);
                            if (ret)
                            {
                                ret = VerifyData(
                                    args->b1_args.root_key.pubkey, EcDsa, hash,
                                    getHashAlgFromTcg(
                                        args->b1_args.cskey.hashalg),
                                    sig, sigLen, &verified);
                                if (ret)
                                {
                                    if (verified)
                                    {
                                        printf("%s%s%s*** CS Key Signature "
                                               "Valid ***%s\n",
                                               getNfo(), setAttribute(Bold),
                                               setAttribute(Green),
                                               setAttribute(Clear));
                                    }
                                    else
                                    {
                                        fprintf(stderr,
                                                "%s%s%s*** CS Key Signature "
                                                "Invalid ***%s\n",
                                                getErr(), setAttribute(Bold),
                                                setAttribute(Red),
                                                setAttribute(Clear));
                                        ret = 0;
                                    }
                                    printf("%s\n", getNfo());
                                    verified = 0;
                                }
                                else
                                {
                                    fprintf(stderr,
                                            "%sVerification function failed\n",
                                            getErr());
                                }
                            }
                            else
                            {
                                fprintf(stderr,
                                        "%s  DER encoding of signature failed",
                                        getErr());
                                ret = 0;
                                // failed to encode DER
                            }
                        }
                        if (hash != NULL)
                        {
                            free(hash);
                            hash = NULL;
                        }
                        if (sig != NULL)
                        {
                            free(sig);
                            sig = NULL;
                        }
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s  Skipping CS Key parsing. PC Type is Key "
                            "Cancellation\n",
                            getWrn());
                    printf("%s\n", getNfo());
                }
                printf("%s  B0 Magic:              0x%08X\n", getNfo(),
                       b1.block0_sig.magic);
                printf("%s  B0 Sig Magic:          0x%08X\n", getNfo(),
                       b1.block0_sig.sig_magic);
                printf("%s  B0 Sig Sig (r):\n", getNfo());
                hexDump(b1.block0_sig.sig_r, 48, "    ", stdout, getNfo());
                printf("%s\n", getNfo());
                printf("%s  B0 Sig Sig (s):\n", getNfo());
                hexDump(b1.block0_sig.sig_s, 48, "    ", stdout, getNfo());
                printf("%s\n", getNfo());
                // If params have been loaded, attempt to verify signatures
                if (args->b1_args.cskey.pubkey != NULL &&
                    args->b1_args.b0sig.hashalg != UINT16_MAX)
                {
                    printf("%s  B0 Sig Signature Verification\n", getNfo());
                    calcSize = sizeof(b0);
                    buff = &b0;
                    ret = HashBuffer(
                        buff, calcSize,
                        getHashAlgFromTcg(args->b1_args.b0sig.hashalg), &hash,
                        &hashLen);
                    if (ret)
                    {
                        printf(
                            "%s  B0 contents %s hash dump:\n", getNfo(),
                            getHashStringFromTcg(args->b1_args.b0sig.hashalg));
                        hexDump(hash, hashLen, "    ", stdout, getNfo());
                        printf("%s\n", getNfo());
                        // do size calculation if 32-48 are 0x00, then we assume
                        // 32
                        int pointLen = EC_POINT_256;
                        for (i = EC_POINT_256; i < EC_POINT_384; ++i)
                        {
                            if (b1.block0_sig.sig_r[i] != 0x00)
                            {
                                pointLen = EC_POINT_384;
                                i = EC_POINT_384; // exit loop
                            }
                        }

                        ret = DerEncodeRs(b1.block0_sig.sig_r,
                                          b1.block0_sig.sig_s, pointLen, &sig,
                                          &sigLen);
                        if (ret)
                        {
                            ret = VerifyData(
                                args->b1_args.cskey.pubkey, EcDsa, hash,
                                getHashAlgFromTcg(args->b1_args.b0sig.hashalg),
                                sig, sigLen, &verified);
                            if (ret)
                            {
                                if (verified)
                                {
                                    printf("%s%s%s*** Block0 Signature Valid "
                                           "***%s\n",
                                           getNfo(), setAttribute(Bold),
                                           setAttribute(Green),
                                           setAttribute(Clear));
                                }
                                else
                                {
                                    fprintf(stderr,
                                            "%s%s%s*** Block0 Signature "
                                            "Invalid ***%s\n",
                                            getErr(), setAttribute(Bold),
                                            setAttribute(Red),
                                            setAttribute(Clear));
                                    ret = 0;
                                }
                                verified = 0;
                            }
                            else
                            {
                                fprintf(stderr,
                                        "%sVerification function failed\n",
                                        getErr());
                            }
                        }
                        else
                        {
                            fprintf(stderr,
                                    "%s  DER encoding of signature failed",
                                    getErr());
                            ret = 0;
                            // failed to encode DER
                        }
                    }
                    if (hash != NULL)
                    {
                        free(hash);
                        hash = NULL;
                    }
                    if (sig != NULL)
                    {
                        free(sig);
                        sig = NULL;
                    }
                }

                printf("%s\n", getNfo());
            }
        }
    }
    else
    {
        fprintf(stderr, "%sFailed to open input file: %s\n", getErr(),
                args->inputBinary);
    }
    if (fp != NULL)
    {
        ret = !(fclose(fp));
        fp = NULL;
    }
    return ret;
}
int generateBlocks(ARGUMENTS *args)
{
    BLOCK_0 b0;
    BLOCK_1 b1;
    // zero out b0 and b1
    memset(&b0, 0x00, sizeof(b0));
    memset(&b1, 0x00, sizeof(b1));
    uint32_t pc_length = 0;
    char *targetFile = args->inputBinary;
    uint32_t actualBlockPad = 0;
    int readChunkSize = 0;
    int writeChunkSize = 0;
    int padamnt = 0;
    int i;
    char chunk[FILE_CHUNK_SIZE];
    int ret = 1;
    char *intermediateFile = NULL;
    FILE *fp = NULL;
    FILE *ifp = NULL;
    unsigned char *qx = NULL;
    unsigned char *qy = NULL;
    uint8_t in[4];
    uint8_t out[4];
    int externalSize = 0;
    void *buff; // generic pointer used for structs/offsets

    // first we need to handle CPLD specific tasks (bytes swapping/svn)
    // if we need to align/add svn/swap bytes, then call buildIntermediateFile.
    if ((args->align != 0 && args->align != UINT32_MAX) ||
        args->svn != UINT32_MAX || args->swapbytes)
    {
        if (args->verbose)
        {
            printf("%sGenerating intermediate file.\n", getNfo());
        }
        int tempLen = (strlen(args->inputBinary) + strlen(ALIGN_TAG) + 1);
        intermediateFile = malloc(tempLen * sizeof(char));
        copy_string(intermediateFile, tempLen, args->inputBinary);
        cat_string(intermediateFile, tempLen, ALIGN_TAG);
        targetFile = intermediateFile;
        ret = openFile(&fp, args->inputBinary, "r");
        if (ret)
        {
            ret = openFile(&ifp, intermediateFile, "w");
            if (ret)
            {
                // Add SVN
                if (args->svn != UINT32_MAX)
                {
                    if (args->verbose)
                    {
                        printf("%sWriting SVN to intermediate file.\n",
                               getNfo());
                    }
                    writeChunkSize =
                        fwrite(&args->svn, sizeof(unsigned char), 4, ifp);
                    if (writeChunkSize != 4)
                    {
                        fprintf(stderr,
                                "%sFailed to write to intermediate file\n",
                                getErr());
                        ret = 0;
                    }
                    else
                    {
                        pc_length += 4;
                    }
                }
                // Perform Byteswap operation
                if (args->swapbytes == 1)
                {
                    if (args->verbose)
                    {
                        printf("%sPerforming byte/bit swap and writing to "
                               "intermediate file.\n",
                               getNfo());
                    }
                    readChunkSize = fread(in, 1, 4, fp);
                    while (readChunkSize == 4)
                    {
                        swapBytesAndBits(in, out);
                        writeChunkSize =
                            fwrite(out, sizeof(unsigned char), 4, ifp);
                        if (writeChunkSize != 4)
                        {
                            fprintf(stderr,
                                    "%sFailed to write to intermediate file.\n",
                                    getErr());
                            ret = 0;
                        }
                        pc_length += writeChunkSize;
                        readChunkSize = fread(in, 1, 4, fp);
                    }
                    if (readChunkSize != 0)
                    {
                        fprintf(stderr,
                                "%sInput binary is not word aligned (4 bytes) "
                                "cannot perform byteswap.\n",
                                getErr());
                        ret = 0;
                    }
                }

                if (args->blockpad != UINT32_MAX && ret)
                {
                    // will default 0 if padding is not specified
                    actualBlockPad = args->blockpad;
                }

                // After byte swapping this will be skipped. No need to add
                // check here.
                readChunkSize = fread(chunk, 1, FILE_CHUNK_SIZE, fp);
                while (readChunkSize == FILE_CHUNK_SIZE && ret)
                {
                    writeChunkSize = fwrite(chunk, sizeof(unsigned char),
                                            FILE_CHUNK_SIZE, ifp);
                    if (writeChunkSize != FILE_CHUNK_SIZE)
                    {
                        ret = 0;
                    }
                    pc_length += writeChunkSize;
                    readChunkSize = fread(chunk, 1, FILE_CHUNK_SIZE, fp);
                }
                writeChunkSize =
                    fwrite(chunk, sizeof(unsigned char), readChunkSize, ifp);
                if (args->svn != UINT32_MAX)
                {
                    padamnt =
                        (args->align) -
                        ((readChunkSize + actualBlockPad + 4) % (args->align));
                }
                else
                {
                    padamnt =
                        (args->align) -
                        ((readChunkSize + actualBlockPad) % (args->align));
                }
                if (padamnt == (args->align))
                {
                    padamnt = 0;
                }
                pc_length += writeChunkSize + padamnt;
                chunk[0] = PAD_CPLD;
                for (i = 0; i < padamnt && ret; ++i)
                {
                    writeChunkSize =
                        fwrite(chunk, sizeof(unsigned char), 1, ifp);
                    if (writeChunkSize != 1)
                    {
                        ret = 0;
                    }
                }
            }
            else
            {
                fprintf(stderr, "%sFailed to write to intermediate file: %s\n",
                        getErr(), intermediateFile);
            }
        }
        else
        {
            fprintf(stderr, "%sFailed to open input file: %s\n", getErr(),
                    args->inputBinary);
        }
    }
    else
    {
        ret = openFile(&fp, args->inputBinary, "r");
        if (ret)
        {
            fseek(fp, 0, SEEK_END);
            pc_length = ftell(fp);
        }
        else
        {
            fprintf(stderr, "%sFailed to open input file: %s\n", getErr(),
                    args->inputBinary);
        }
    }
    if (fp != NULL)
    {
        // fclose is 0 on success
        if (ret)
        {
            ret = !(fclose(fp));
        }
        else
        {
            fclose(fp);
        }
        fp = NULL;
    }
    if (ifp != NULL)
    {
        // fclose is 0 on success
        if (ret)
        {
            ret = !(fclose(ifp));
        }
        else
        {
            fclose(ifp);
        }

        ifp = NULL;
    }
    // build the blocks
    if (ret)
    {
        if (args->verbose)
        {
            printf("%sPopulating Block0 structure.\n", getNfo());
        }
        // BLOCK 0
        b0.magic = args->b0_args.magic;
        b0.pc_length = pc_length;
        b0.pc_type = args->b0_args.pctype;
        memset(b0.reserved1, PAD_BLOCK, sizeof(b0.reserved1));
        unsigned char *hashBuffer = NULL;
        int size = 0;
        int calcSize = 0;
        unsigned char *sig = NULL;
        int sigLen = 0;
        unsigned char *r = NULL;
        unsigned char *s = NULL;
        ret = HashFile(targetFile, Sha256, &hashBuffer, &size);
        if (ret)
        {
            copy_memory(b0.sha256, sizeof(b0.sha256), hashBuffer, size);
            free(hashBuffer);
            hashBuffer = NULL;
        }
        ret = HashFile(targetFile, Sha384, &hashBuffer, &size);
        if (ret)
        {
            copy_memory(b0.sha384, sizeof(b0.sha384), hashBuffer, size);
            free(hashBuffer);
            hashBuffer = NULL;
        }
        if (ret)
        {
            if (args->verbose)
            {
                printf("%sPopulating Block1 structure.\n", getNfo());
            }
            // BLOCK 1 GLOBAL
            b1.magic = args->b1_args.magic;
            // BLOCK 1 ROOT KEY
            if (args->verbose)
            {
                printf("%s  Generating Root Key structure.\n", getNfo());
            }
            b1.root_key.curve_magic = args->b1_args.root_key.curve_magic;
            b1.root_key.keyid = args->b1_args.root_key.keyid;
            b1.root_key.magic = args->b1_args.root_key.magic;
            b1.root_key.permissions = args->b1_args.root_key.permissions;

            ret = ExtractQxQyFromPubkey(args->b1_args.root_key.pubkey, &qx, &qy,
                                        &size);
            if (ret)
            {
                if (size <= 48)
                {
                    for (i = 0; i < size; ++i)
                    {
                        b1.root_key.pubkey_x[i] = qx[i];
                        b1.root_key.pubkey_y[i] = qy[i];
                    }
                }
                else
                {
                    // got bad size
                    ret = 0;
                }
            }
            if (qx != NULL)
            {
                free(qx);
                qx = NULL;
            }
            if (qy != NULL)
            {
                free(qy);
                qy = NULL;
            }
        }
        // BLOCK 1 CSKEY - Skip if KEY CANCELLATION
        if (ret && !(b0.pc_type & CANCELLATION_BIT))
        {
            if (args->verbose)
            {
                printf("%s  Generating Code Signing Key structure.\n",
                       getNfo());
            }
            b1.cs_key.curve_magic = args->b1_args.cskey.curve_magic;
            b1.cs_key.keyid = args->b1_args.cskey.keyid;
            b1.cs_key.magic = args->b1_args.cskey.magic;
            b1.cs_key.permissions = args->b1_args.cskey.permissions;
            ret = ExtractQxQyFromPubkey(args->b1_args.cskey.pubkey, &qx, &qy,
                                        &size);
            if (ret)
            {
                if (size <= EC_POINT_MAX)
                {
                    for (i = 0; i < size; ++i)
                    {
                        b1.cs_key.pubkey_x[i] = qx[i];
                        b1.cs_key.pubkey_y[i] = qy[i];
                    }
                }
                else
                {
                    // got bad size
                    ret = 0;
                }
            }
            if (qx != NULL)
            {
                free(qx);
                qx = NULL;
            }
            if (qy != NULL)
            {
                free(qy);
                qy = NULL;
            }
            if (ret)
            {
                b1.cs_key.sig_magic = args->b1_args.cskey.sig_magic;

                if (args->verbose)
                {
                    printf(
                        "%s    Calculating data buffer and hashing with %s.\n",
                        getNfo(),
                        getHashStringFromTcg(args->b1_args.cskey.hashalg));
                }
                // calculate the size of the buffer that we should hash (this
                // should prevent accessing bad mem)
                calcSize = // sizeof(b1.cs_key.magic) +
                    sizeof(b1.cs_key.curve_magic) +
                    sizeof(b1.cs_key.permissions) + sizeof(b1.cs_key.keyid) +
                    sizeof(b1.cs_key.pubkey_x) + sizeof(b1.cs_key.pubkey_y) +
                    sizeof(b1.cs_key.reserved1); /* +
                     sizeof(b1.cs_key.sig_magic);
                 buff = &(b1.cs_key.magic);*/
                buff = &(b1.cs_key.curve_magic);
                ret = HashBuffer(buff, calcSize,
                                 getHashAlgFromTcg(args->b1_args.cskey.hashalg),
                                 &hashBuffer, &size);
                if (args->verbose)
                {
                    printf("%s    Hash Dump:\n", getNfo());
                    hexDump(hashBuffer, size, "      ", stdout, getNfo());
                }
                if (ret)
                {
                    if (args->b1_args.cskey.sign_key != NULL)
                    {
                        if (args->verbose)
                        {
                            printf("%s    Signing hash with key %s.\n",
                                   getNfo(), args->b1_args.cskey.sign_key);
                        }
                        ret = SignData(
                            args->b1_args.cskey.sign_key, EcDsa, hashBuffer,
                            getHashAlgFromTcg(args->b1_args.cskey.hashalg),
                            &sig, &sigLen);
                        if (ret)
                        {
                            ret = ExtractRs(sig, sigLen, &r, &s, &size);
                            if (ret)
                            {
                                if (args->verbose)
                                {
                                    printf("%s    Sig(r):\n", getNfo());
                                    hexDump(r, size, "      ", stdout,
                                            getNfo());
                                    printf("%s    Sig(s):\n", getNfo());
                                    hexDump(s, size, "      ", stdout,
                                            getNfo());
                                }
                                if (size > EC_POINT_MAX)
                                {
                                    fprintf(stderr,
                                            "%sSig(r/s) points are too large. "
                                            "Current implementation supports "
                                            "up to 384 bit prime field (i.e. "
                                            "secp384r1).\n",
                                            getErr());
                                    ret = 0;
                                }

                                // Check the signature for 0s
                                ret = zeroCheckSig(r, s, size);

                                // Copy signature into data structure.
                                for (i = 0; i < size && ret; ++i)
                                {
                                    b1.cs_key.sig_r[i] = r[i];
                                    b1.cs_key.sig_s[i] = s[i];
                                }
                                free(r);
                                r = NULL;
                                free(s);
                                s = NULL;
                            }
                            free(sig);
                        }
                    }
                    else
                    {
                        ret =
                            doExternalSign(buff, calcSize, hashBuffer, size,
                                           args->b1_args.cskey.script_file, &r,
                                           &s, &externalSize, args->verbose);
                        if (ret)
                        {
                            if (args->verbose)
                            {
                                printf("%s    Sig(r):\n", getNfo());
                                hexDump(r, externalSize, "      ", stdout,
                                        getNfo());
                                printf("%s    Sig(s):\n", getNfo());
                                hexDump(s, externalSize, "      ", stdout,
                                        getNfo());
                            }
                            if (externalSize > EC_POINT_MAX)
                            {
                                fprintf(
                                    stderr,
                                    "%sSig(r/s) points are too large. Current "
                                    "implementation supports up to 384 bit "
                                    "prime field (i.e. secp384r1).\n",
                                    getErr());
                                ret = 0;
                            }
                            // Check signature for all 0s
                            ret = zeroCheckSig(r, s, externalSize);

                            // Copy the signature into the data structure.
                            for (i = 0; i < externalSize && ret; ++i)
                            {
                                b1.cs_key.sig_r[i] = r[i];
                                b1.cs_key.sig_s[i] = s[i];
                            }
                        }
                        if (r != NULL)
                        {
                            free(r);
                            r = NULL;
                        }
                        if (s != NULL)
                        {
                            free(s);
                            s = NULL;
                        }
                    }
                    free(hashBuffer);
                    hashBuffer = NULL;
                }
            }
        }
        // BLOCK1 BLOCK0_SIG
        if (ret)
        {
            if (args->verbose)
            {
                printf("%s  Generating Block0 Signature Structure\n", getNfo());
            }
            b1.block0_sig.magic = args->b1_args.b0sig.magic;
            b1.block0_sig.sig_magic = args->b1_args.b0sig.sig_magic;
            buff = &b0;
            calcSize = sizeof(b0);
            if (args->verbose)
            {
                printf("%s    Hashing Block0 with %s.\n", getNfo(),
                       getHashStringFromTcg(args->b1_args.b0sig.hashalg));
            }
            ret = HashBuffer(buff, calcSize,
                             getHashAlgFromTcg(args->b1_args.b0sig.hashalg),
                             &hashBuffer, &size);
            if (args->verbose)
            {
                printf("%s    Hash Dump:\n", getNfo());
                hexDump(hashBuffer, size, "      ", stdout, getNfo());
            }
            if (ret)
            {
                if (args->b1_args.b0sig.sign_key != NULL)
                {
                    if (args->verbose)
                    {
                        printf("%s    Signing hash with key %s\n", getNfo(),
                               args->b1_args.b0sig.sign_key);
                    }
                    ret = SignData(
                        args->b1_args.b0sig.sign_key, EcDsa, hashBuffer,
                        getHashAlgFromTcg(args->b1_args.b0sig.hashalg), &sig,
                        &sigLen);
                    if (ret)
                    {
                        ret = ExtractRs(sig, sigLen, &r, &s, &size);
                        if (ret)
                        {
                            if (args->verbose)
                            {
                                {
                                    printf("%s    Sig(r):\n", getNfo());
                                    hexDump(r, size, "      ", stdout,
                                            getNfo());
                                    printf("%s    Sig(s):\n", getNfo());
                                    hexDump(s, size, "      ", stdout,
                                            getNfo());
                                }
                            }
                            if (size > EC_POINT_MAX)
                            {
                                // curve points too big, unsupported. 384 or
                                // smaller
                                ret = 0;
                            }

                            // Check signature for all 0s
                            ret = zeroCheckSig(r, s, size);

                            for (i = 0; i < size && ret; ++i)
                            {
                                b1.block0_sig.sig_r[i] = r[i];
                                b1.block0_sig.sig_s[i] = s[i];
                            }
                            free(r);
                            free(s);
                        }
                        free(sig);
                    }
                }
                else
                {
                    ret = doExternalSign(buff, calcSize, hashBuffer, size,
                                         args->b1_args.b0sig.script_file, &r,
                                         &s, &externalSize, args->verbose);
                    if (ret)
                    {
                        if (args->verbose)
                        {
                            printf("%s    Sig(r):\n", getNfo());
                            hexDump(r, externalSize, "      ", stdout,
                                    getNfo());
                            printf("%s    Sig(s):\n", getNfo());
                            hexDump(s, externalSize, "      ", stdout,
                                    getNfo());
                        }
                        if (externalSize > EC_POINT_MAX)
                        {
                            fprintf(stderr,
                                    "%sSig(r/s) points are too large. Current "
                                    "implementation supports up to 384 bit "
                                    "prime field (i.e. secp384r1).\n",
                                    getErr());
                            ret = 0;
                        }

                        // Check signature for all 0s
                        ret = zeroCheckSig(r, s, externalSize);

                        for (i = 0; i < externalSize && ret; ++i)
                        {
                            b1.block0_sig.sig_r[i] = r[i];
                            b1.block0_sig.sig_s[i] = s[i];
                        }
                    }
                    if (r != NULL)
                    {
                        free(r);
                        r = NULL;
                    }
                    if (s != NULL)
                    {
                        free(s);
                        s = NULL;
                    }
                }
                free(hashBuffer);
                hashBuffer = NULL;
            }
        }
    }
    if (ret)
    {
        if (args->verbose)
        {
            printf("%sWriting blocks and protected content to output file.\n",
                   getNfo());
        }
        ret = openFile(&fp, targetFile, "r");
        if (ret)
        {
            ret = openFile(&ifp, args->outputBinary, "w");
            if (ret)
            {
                if (args->blockpad != UINT32_MAX)
                {
                    if (args->verbose)
                    {
                        printf(
                            "%s  Calculating amount of bytes to pad blocks.\n",
                            getNfo());
                    }
                    // recalculate padding now that we know the size of the
                    // blocks
                    actualBlockPad = sizeof(b0);
                    actualBlockPad += sizeof(b1.magic);
                    actualBlockPad += sizeof(b1.reserved1);
                    actualBlockPad += sizeof(b1.root_key);
                    if (!(b0.pc_type & CANCELLATION_BIT))
                    {
                        actualBlockPad += sizeof(b1.cs_key);
                    }
                    actualBlockPad += sizeof(b1.block0_sig);
                    actualBlockPad = (args->blockpad - actualBlockPad);
                }
                else
                {
                    actualBlockPad = 0;
                }

                if (args->verbose)
                {
                    printf("%s  Writing Block0.\n", getNfo());
                }
                writeChunkSize =
                    fwrite(&b0, sizeof(unsigned char), sizeof(b0), ifp);
                if (args->verbose)
                {
                    printf("%s  Writing Block1.\n", getNfo());
                }
                writeChunkSize = fwrite(&(b1.magic), sizeof(unsigned char),
                                        sizeof(b1.magic), ifp);
                writeChunkSize = fwrite(&(b1.reserved1), sizeof(unsigned char),
                                        sizeof(b1.reserved1), ifp);
                writeChunkSize = fwrite(&(b1.root_key), sizeof(unsigned char),
                                        sizeof(b1.root_key), ifp);
                if (!(b0.pc_type & CANCELLATION_BIT))
                {
                    writeChunkSize = fwrite(&(b1.cs_key), sizeof(unsigned char),
                                            sizeof(b1.cs_key), ifp);
                }
                else if (args->verbose)
                {
                    printf("%s  PC Type is key cancellation, skipping Block 1 "
                           "CSK structure.\n",
                           getNfo());
                }
                writeChunkSize = fwrite(&(b1.block0_sig), sizeof(unsigned char),
                                        sizeof(b1.block0_sig), ifp);
                chunk[0] = PAD_BLOCK;
                if (args->verbose && (int)actualBlockPad > 0)
                {
                    printf(
                        "%s  Padding %d bytes (0x00) to the end of Block1.\n",
                        getNfo(), actualBlockPad);
                }
                for (i = 0; i < (int)actualBlockPad; ++i)
                {
                    writeChunkSize =
                        fwrite(chunk, sizeof(unsigned char), 1, ifp);
                }
                if (args->verbose)
                {
                    printf("%s  Catting file %s after blocks.\n", getNfo(),
                           targetFile);
                }
                readChunkSize = fread(chunk, 1, FILE_CHUNK_SIZE, fp);
                while (readChunkSize == FILE_CHUNK_SIZE && ret)
                {
                    writeChunkSize = fwrite(chunk, sizeof(unsigned char),
                                            FILE_CHUNK_SIZE, ifp);
                    if (writeChunkSize != FILE_CHUNK_SIZE)
                    {
                        ret = 0;
                    }
                    pc_length += writeChunkSize;
                    readChunkSize = fread(chunk, 1, FILE_CHUNK_SIZE, fp);
                }
                writeChunkSize =
                    fwrite(chunk, sizeof(unsigned char), readChunkSize, ifp);
                if (args->verbose)
                {
                    printf("%sCompleted successfully!\n", getNfo());
                }
            }
            else
            {
                fprintf(stderr, "%sFailed to write to output file: %s\n",
                        getErr(), args->outputBinary);
            }
        }
        else
        {
            fprintf(stderr, "%sFailed to open file %s\n", getErr(), targetFile);
        }
        if (fp != NULL)
        {
            // fclose is 0 on success
            ret = !(fclose(fp));
            fp = NULL;
        }
        if (ifp != NULL)
        {
            // fclose is 0 on success
            ret = !(fclose(ifp));
            ifp = NULL;
        }
    }

    if (intermediateFile != NULL)
    {
        free(intermediateFile);
    }
    return ret;
}
int doBlocksign(ARGUMENTS *args)
{
    int ret;
    if (args->parse)
    {
        ret = parseBlocks(args);
    }
    else
    {
        ret = generateBlocks(args);
    }
    return ret;
}
