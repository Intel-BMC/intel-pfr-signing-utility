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
#include "argparse.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <string.h>

#include "args.h"
#include "log.h"
#include "s_helpers.h"
#include "tcg.h"
#ifdef _WIN32
#include <direct.h>
#else
#include <linux/limits.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

int truncateFilePath(char *path)
{
    int ret = 0;
    int i;
    for (i = strlen(path); i >= 0; --i)
    {
        if (path[i] == '/' || path[i] == '\\')
        {
            path[i + 1] = '\0';
            ret = 1;
            i = -1;
        }
    }
    return ret;
}
/// Allocate and ARGUMENTS struct, and set all values to default
void initContext(ARGUMENTS **args)
{
    *args = malloc(sizeof(ARGUMENTS));
    // Set head to NULL (there are 0 keys)
    // set initial values for input validation
    (*args)->b1_args.cskey.curve_magic = UINT32_MAX;
    (*args)->b1_args.cskey.keyid = INT32_MAX;
    (*args)->b1_args.cskey.magic = UINT32_MAX;
    (*args)->b1_args.cskey.permissions = INT32_MAX;
    (*args)->b1_args.cskey.script_file = NULL;
    (*args)->b1_args.cskey.sign_key = NULL;
    (*args)->b1_args.cskey.pubkey = NULL;
    (*args)->b1_args.cskey.hashalg = UINT16_MAX;
    (*args)->b1_args.cskey.sig_magic = UINT32_MAX;
    (*args)->b0_args.magic = UINT32_MAX;
    (*args)->b0_args.pctype = UINT32_MAX;
    (*args)->b1_args.magic = UINT32_MAX;
    (*args)->b1_args.root_key.keyid = INT32_MAX;
    (*args)->b1_args.root_key.magic = UINT32_MAX;
    (*args)->b1_args.root_key.curve_magic = UINT32_MAX;
    (*args)->b1_args.root_key.permissions = INT32_MAX;
    (*args)->b1_args.root_key.pubkey = NULL;
    (*args)->b1_args.b0sig.hashalg = UINT16_MAX;
    (*args)->b1_args.b0sig.magic = UINT32_MAX;
    (*args)->b1_args.b0sig.script_file = NULL;
    (*args)->b1_args.b0sig.sign_key = NULL;
    (*args)->b1_args.b0sig.sig_magic = UINT32_MAX;
    (*args)->inputBinary = NULL;
    (*args)->outputBinary = NULL;
    (*args)->align = UINT32_MAX;
    (*args)->blockpad = UINT32_MAX;
    (*args)->parse = 0;
    (*args)->verbose = 0;
    (*args)->version = UINT8_MAX;
    (*args)->swapbytes = UINT8_MAX;
    (*args)->svn = UINT32_MAX;
}

/// Destroy the argument context, ensuring all memory is freed
void destroyContext(ARGUMENTS *args)
{
    if (args != NULL)
    {
        if (args->b1_args.root_key.pubkey != NULL)
        {
            free(args->b1_args.root_key.pubkey);
        }
        if (args->b1_args.cskey.pubkey != NULL)
        {
            free(args->b1_args.cskey.pubkey);
        }
        if (args->b1_args.cskey.script_file != NULL)
        {
            free(args->b1_args.cskey.script_file);
        }
        if (args->b1_args.cskey.sign_key != NULL)
        {
            free(args->b1_args.cskey.sign_key);
        }
        if (args->inputBinary != NULL)
        {
            free(args->inputBinary);
        }
        if (args->outputBinary != NULL)
        {
            free(args->outputBinary);
        }
        if (args->b1_args.b0sig.script_file != NULL)
        {
            free(args->b1_args.b0sig.script_file);
        }
        if (args->b1_args.b0sig.sign_key != NULL)
        {
            free(args->b1_args.b0sig.sign_key);
        }
        free(args);
    }
}

/// Check a block to see if the node->name matches
int checkBlock(xmlNode *node, const char *name)
{
    int ret = 0;
    if (node != NULL)
    {
        char *upper;
        toUpper(node->name, &upper);
        if (strcmp(upper, name) == 0)
        {
            ret = 1;
        }
        free(upper);
    }
    return ret;
}

/// Validates input (32-bit hex), and sets a value (unsigned 32-bit integer)
int setUint32Hex(uint32_t *set, const unsigned char *val, int line_num)
{
    int i;
    int ret = 1;
    char *upper;
    toUpper(val, &upper);
    int length = strlen(upper);
    // sanity check
    for (i = 0; i < length && ret; ++i)
    {
        if (!(upper[i] == '0' || upper[i] == 'X' ||
              (upper[i] >= 'A' && upper[i] <= 'F') ||
              (upper[i] >= '0' && upper[i] <= '9')))
        {
            ret = 0;
        }
        if (upper[i] == 'X' && i != 1)
        {
            ret = 0;
        }
    }
    free(upper);
    if (ret)
    {
        *set = (uint32_t)strtoul((char *)val, NULL, 16);
        if (errno == ERANGE)
        {
            fprintf(stderr, "%s%s is too large. Line: %d\n", getErr(), val,
                    line_num);
            ret = 0;
        }
    }
    else
    {
        fprintf(stderr, "%sFailed to parse HEX value at line: %d. Check XML.\n",
                getErr(), line_num);
    }
    return ret;
}

/// Validates input (32-bit integer decimal), and sets a value (unsigned 32-bit
/// integer)
int setInt32Dec(int32_t *set, const unsigned char *val, int line_num)
{
    int i;
    int ret = 1;

    int length = strlen((char *)val);
    // sanity check
    for (i = 0; i < length && ret; ++i)
    {
        if (!(val[i] == '-' || (val[i] >= '0' && val[i] <= '9')))
        {
            ret = 0;
        }
    }
    if (ret)
    {
        *set = (int32_t)strtol((char *)val, NULL, 10);
        if (errno == ERANGE)
        {
            fprintf(stderr, "%s%s is too large. Line: %d\n", getErr(), val,
                    line_num);
            ret = 0;
        }
    }
    else
    {
        fprintf(stderr, "%sFailed to parse DEC value at line: %d. Check XML.\n",
                getErr(), line_num);
    }
    return ret;
}

int setUint8Dec(uint8_t *set, const unsigned char *val, int line_num)
{
    int i;
    int ret = 1;

    int length = strlen((char *)val);
    // sanity check
    for (i = 0; i < length && ret; ++i)
    {
        if (!(val[i] == '-' || (val[i] >= '0' && val[i] <= '9')))
        {
            ret = 0;
        }
    }
    if (ret)
    {
        uint32_t test = (uint32_t)strtoul((char *)val, NULL, 10);
        if (errno == ERANGE)
        {
            fprintf(stderr, "%s%s is too large. Line: %d\n", getErr(), val,
                    line_num);
            ret = 0;
        }
        else if (test > 255)
        {
            fprintf(stderr, "%s%s is too large. Line: %d\n", getErr(), val,
                    line_num);
            ret = 0;
        }
        else
        {
            *set = (uint8_t)test;
        }
    }
    else
    {
        fprintf(stderr, "%sFailed to parse DEC value at line: %d. Check XML.\n",
                getErr(), line_num);
    }
    return ret;
}

/// Validates input (32-bit unsigned integer decimal), and sets a value
/// (unsigned 32-bit integer)
int setUint32Dec(uint32_t *set, const unsigned char *val, int line_num)
{
    int i;
    int ret = 1;

    int length = strlen((char *)val);
    // sanity check
    for (i = 0; i < length && ret; ++i)
    {
        if (!(val[i] == '-' || (val[i] >= '0' && val[i] <= '9')))
        {
            ret = 0;
        }
    }
    if (ret)
    {
        *set = (uint32_t)strtoul((char *)val, NULL, 10);
        if (errno == ERANGE)
        {
            fprintf(stderr, "%s%s is too large. Line: %d\n", getErr(), val,
                    line_num);
            ret = 0;
        }
    }
    else
    {
        fprintf(stderr, "%sFailed to parse DEC value at line: %d. Check XML.\n",
                getErr(), line_num);
    }
    return ret;
}

/// Validates input (HashAlg string), and sets a value (TCG 16-bit value)
int setHashAlg(uint16_t *set, const unsigned char *val, int line_num)
{
    int ret = 1;
    char *upper;
    toUpper(val, &upper);
    if (strcmp(upper, HASH_SHA1_STR) == 0)
    {
        *set = TPM_ALG_SHA1;
    }
    else if (strcmp(upper, HASH_SHA256_STR) == 0)
    {
        *set = TPM_ALG_SHA256;
    }
    else if (strcmp(upper, HASH_SHA384_STR) == 0)
    {
        *set = TPM_ALG_SHA384;
    }
    else if (strcmp(upper, HASH_SHA512_STR) == 0)
    {
        *set = TPM_ALG_SHA512;
    }
    else
    {
        fprintf(
            stderr,
            "%sUnknown hash algorithm \"%s\" at line: %d. Check XML syntax\n",
            getErr(), val, line_num);
        ret = 0;
    }
    free(upper);
    return ret;
}

/// Validates input (True/False), and sets a value (1/0)
int setTrueFalse(uint8_t *set, const unsigned char *val, int line_num)
{
    int ret = 1;
    char *upper;
    toUpper(val, &upper);
    if (strcmp(upper, TAG_TRUE) == 0)
    {
        *set = 1;
    }
    else if (strcmp(upper, TAG_FALSE) == 0)
    {
        *set = 0;
    }
    else
    {
        fprintf(stderr,
                "%sUnknown boolean value \"%s\" at line: %d. %s or %s are "
                "acceptable values. Check XML syntax\n",
                getErr(), val, line_num, TAG_TRUE, TAG_FALSE);
        ret = 0;
    }

    free(upper);
    return ret;
}

// unique parent elements
int block0_set = 0;
int block1_set = 0;
int padding_set = 0;
int cskey_set = 0;
int b0sig_set = 0;
int rootkey_set = 0;

/// Main recursive parser function. Iterates over XML tree setting values in
/// argument structure
int parseElements(xmlNode *node, ARGUMENTS *args)
{
    int tempLen;
    int healthy = 1;
    xmlNode *cur_node = NULL;
    // Hit lowest common denominators and set values
    for (cur_node = node->children; cur_node && healthy;
         cur_node = cur_node->next)
    {
        if (cur_node->children != NULL)
        {
            // Handle Magic
            if (checkBlock(cur_node, ELEMENT_MAGIC) && healthy)
            {
                if (checkBlock(cur_node->parent, ELEMENT_BLOCK0))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b0_args.magic != UINT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_BLOCK0, ELEMENT_MAGIC,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setUint32Hex(&(args->b0_args.magic),
                                                   cur_node->children->content,
                                                   cur_node->line);
                        }
                    }
                }
                else if (checkBlock(cur_node->parent, ELEMENT_BLOCK1))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.magic != UINT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_BLOCK1, ELEMENT_MAGIC,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setUint32Hex(&(args->b1_args.magic),
                                                   cur_node->children->content,
                                                   cur_node->line);
                        }
                    }
                }
                else if (checkBlock(cur_node->parent, ELEMENT_RKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.root_key.magic != UINT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_RKEY, ELEMENT_MAGIC,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setUint32Hex(
                                &(args->b1_args.root_key.magic),
                                cur_node->children->content, cur_node->line);
                        }
                    }
                }
                else if (checkBlock(cur_node->parent, ELEMENT_CSKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.cskey.magic != UINT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_CSKEY, ELEMENT_MAGIC,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setUint32Hex(&(args->b1_args.cskey.magic),
                                                   cur_node->children->content,
                                                   cur_node->line);
                        }
                    }
                }
                else if (checkBlock(cur_node->parent, ELEMENT_B0SIG))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.b0sig.magic != UINT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_B0SIG, ELEMENT_MAGIC,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setUint32Hex(&(args->b1_args.b0sig.magic),
                                                   cur_node->children->content,
                                                   cur_node->line);
                        }
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s%s was unexpected, line: %d. Check XML Syntax\n",
                            getErr(), ELEMENT_MAGIC, cur_node->line);
                    healthy = 0;
                }
            }

            // Handle Sig Magic
            else if (checkBlock(cur_node, ELEMENT_SIGMAGIC) && healthy)
            {
                if (checkBlock(cur_node->parent, ELEMENT_CSKEY))
                {
                    if (args->b1_args.cskey.sig_magic != UINT32_MAX)
                    {
                        fprintf(stderr,
                                "%s%s %s has a duplicate argument, line: %d. "
                                "Check XML syntax.\n",
                                getErr(), ELEMENT_CSKEY, ELEMENT_SIGMAGIC,
                                cur_node->line);
                        healthy = 0;
                    }
                    else
                    {
                        healthy = setUint32Hex(&(args->b1_args.cskey.sig_magic),
                                               cur_node->children->content,
                                               cur_node->line);
                    }
                }
                else if (checkBlock(cur_node->parent, ELEMENT_B0SIG))
                {
                    if (args->b1_args.b0sig.sig_magic != UINT32_MAX)
                    {
                        fprintf(stderr,
                                "%s%s %s has a duplicate argument, line: %d. "
                                "Check XML syntax.\n",
                                getErr(), ELEMENT_B0SIG, ELEMENT_SIGMAGIC,
                                cur_node->line);
                        healthy = 0;
                    }
                    else
                    {
                        healthy = setUint32Hex(&(args->b1_args.b0sig.sig_magic),
                                               cur_node->children->content,
                                               cur_node->line);
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s%s was unexpected, line: %d. Check XML Syntax\n",
                            getErr(), ELEMENT_SIGMAGIC, cur_node->line);
                    healthy = 0;
                }
            }

            // Handle Curve Magic
            else if (checkBlock(cur_node, ELEMENT_CURVEMAGIC) && healthy)
            {
                // CSKEY CURVE MAGIC
                if (checkBlock(cur_node->parent, ELEMENT_CSKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.cskey.curve_magic != UINT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_CSKEY, ELEMENT_CURVEMAGIC,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setUint32Hex(
                                &(args->b1_args.cskey.curve_magic),
                                cur_node->children->content, cur_node->line);
                        }
                    }
                }
                // RKEY CURVE MAGIC
                else if (checkBlock(cur_node->parent, ELEMENT_RKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.root_key.curve_magic != UINT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_RKEY, ELEMENT_CURVEMAGIC,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setUint32Hex(
                                &(args->b1_args.root_key.curve_magic),
                                cur_node->children->content, cur_node->line);
                        }
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s%s was unexpected, line: %d. Check XML Syntax\n",
                            getErr(), ELEMENT_CURVEMAGIC, cur_node->line);
                    healthy = 0;
                }
            }

            // Handle PC Type
            else if (checkBlock(cur_node, ELEMENT_PCTYPE))
            {
                if (checkBlock(cur_node->parent, ELEMENT_BLOCK0))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b0_args.pctype != UINT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s has a duplicate argument, line: %d. "
                                    "Check XML syntax.\n",
                                    getErr(), ELEMENT_PCTYPE, cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setUint32Dec(&(args->b0_args.pctype),
                                                   cur_node->children->content,
                                                   cur_node->line);
                        }
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s%s was unexpected, line: %d. Check XML Syntax\n",
                            getErr(), ELEMENT_PCTYPE, cur_node->line);
                    healthy = 0;
                }
            }
            // Handle Permissions
            else if (checkBlock(cur_node, ELEMENT_PERMISSIONS))
            {
                if (checkBlock(cur_node->parent, ELEMENT_RKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.root_key.permissions != INT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_RKEY, ELEMENT_PERMISSIONS,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setInt32Dec(
                                &(args->b1_args.root_key.permissions),
                                cur_node->children->content, cur_node->line);
                        }
                    }
                }
                else if (checkBlock(cur_node->parent, ELEMENT_CSKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.cskey.permissions != INT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_CSKEY,
                                    ELEMENT_PERMISSIONS, cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setInt32Dec(
                                &(args->b1_args.cskey.permissions),
                                cur_node->children->content, cur_node->line);
                        }
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%sPERMISSIONS was unexpected, line: %d. Check XML "
                            "Syntax\n",
                            getErr(), cur_node->line);
                }
            }
            // Handle Key ID
            else if (checkBlock(cur_node, ELEMENT_KEYID) && healthy)
            {
                if (checkBlock(cur_node->parent, ELEMENT_RKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.root_key.keyid != INT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_RKEY, ELEMENT_KEYID,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setInt32Dec(
                                &(args->b1_args.root_key.keyid),
                                cur_node->children->content, cur_node->line);
                        }
                    }
                }
                else if (checkBlock(cur_node->parent, ELEMENT_CSKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.cskey.keyid != INT32_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_CSKEY, ELEMENT_KEYID,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setInt32Dec(&(args->b1_args.cskey.keyid),
                                                  cur_node->children->content,
                                                  cur_node->line);
                        }
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s%s was unexpected, line: %d. Check XML Syntax\n",
                            getErr(), ELEMENT_KEYID, cur_node->line);
                    healthy = 0;
                }
            }

            // Handle Key File
            else if (checkBlock(cur_node, ELEMENT_PUBKEY) && healthy)
            {
                if (checkBlock(cur_node->parent, ELEMENT_RKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.root_key.pubkey != NULL)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_RKEY, ELEMENT_PUBKEY,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            // args->b1_args.root_key.pubkey =
                            // cur_node->children->content;
                            tempLen =
                                strlen((char *)(cur_node->children->content)) +
                                1;
                            args->b1_args.root_key.pubkey =
                                malloc(tempLen * sizeof(char));
                            copy_string(args->b1_args.root_key.pubkey, tempLen,
                                        cur_node->children->content);
                        }
                    }
                }
                else if (checkBlock(cur_node->parent, ELEMENT_CSKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.cskey.pubkey != NULL)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_CSKEY, ELEMENT_PUBKEY,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            tempLen =
                                strlen((char *)(cur_node->children->content)) +
                                1;
                            args->b1_args.cskey.pubkey =
                                malloc(tempLen * sizeof(char));
                            copy_string(args->b1_args.cskey.pubkey, tempLen,
                                        cur_node->children->content);
                        }
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s%s was unexpected, line: %d. Check XML Syntax\n",
                            getErr(), ELEMENT_PUBKEY, cur_node->line);
                    healthy = 0;
                }
            }

            // Handle Sign Key
            else if (checkBlock(cur_node, ELEMENT_SIGNKEY) && healthy)
            {
                if (checkBlock(cur_node->parent, ELEMENT_CSKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.cskey.script_file == NULL)
                        {
                            if (args->b1_args.cskey.sign_key != NULL)
                            {
                                fprintf(stderr,
                                        "%s%s %s has a duplicate argument, "
                                        "line: %d. Check XML syntax.\n",
                                        getErr(), ELEMENT_CSKEY,
                                        ELEMENT_SIGNKEY, cur_node->line);
                                healthy = 0;
                            }
                            else
                            {
                                tempLen =
                                    strlen(
                                        (char *)(cur_node->children->content)) +
                                    1;
                                args->b1_args.cskey.sign_key =
                                    malloc(tempLen * sizeof(char));
                                copy_string(args->b1_args.cskey.sign_key,
                                            tempLen,
                                            cur_node->children->content);
                            }
                        }
                        else
                        {
                            fprintf(stderr,
                                    "%s%s and %s cannot be assigned to the "
                                    "same %s, line: %d. Check XML Syntax\n",
                                    getErr(), ELEMENT_SCRIPT, ELEMENT_SIGNKEY,
                                    ELEMENT_CSKEY, cur_node->line);
                            healthy = 0;
                        }
                    }
                }
                else if (checkBlock(cur_node->parent, ELEMENT_B0SIG))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.b0sig.script_file == NULL)
                        {
                            if (args->b1_args.b0sig.sign_key != NULL)
                            {
                                fprintf(stderr,
                                        "%s%s %s has a duplicate argument, "
                                        "line: %d. Check XML syntax.\n",
                                        getErr(), ELEMENT_B0SIG,
                                        ELEMENT_SIGNKEY, cur_node->line);
                                healthy = 0;
                            }
                            else
                            {
                                tempLen =
                                    strlen(
                                        (char *)(cur_node->children->content)) +
                                    1;
                                args->b1_args.b0sig.sign_key =
                                    malloc(tempLen * sizeof(char));
                                copy_string(args->b1_args.b0sig.sign_key,
                                            tempLen,
                                            cur_node->children->content);
                            }
                        }
                        else
                        {
                            fprintf(stderr,
                                    "%s%s and %s cannot be assigned to the "
                                    "same %s, line: %d. Check XML Syntax\n",
                                    getErr(), ELEMENT_SCRIPT, ELEMENT_SIGNKEY,
                                    ELEMENT_B0SIG, cur_node->line);
                            healthy = 0;
                        }
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s%s was unexpected, line: %d. Check XML Syntax\n",
                            getErr(), ELEMENT_SIGNKEY, cur_node->line);
                    healthy = 0;
                }
            }

            // Handle Script File
            else if (checkBlock(cur_node, ELEMENT_SCRIPT) && healthy)
            {
                if (checkBlock(cur_node->parent, ELEMENT_CSKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.cskey.sign_key == NULL)
                        {
                            if (args->b1_args.cskey.script_file != NULL)
                            {
                                fprintf(stderr,
                                        "%s%s %s has a duplicate argument, "
                                        "line: %d. Check XML syntax.\n",
                                        getErr(), ELEMENT_CSKEY, ELEMENT_SCRIPT,
                                        cur_node->line);
                                healthy = 0;
                            }
                            else
                            {
                                tempLen =
                                    strlen(
                                        (char *)(cur_node->children->content)) +
                                    1;
                                args->b1_args.cskey.script_file =
                                    malloc(tempLen * sizeof(char));
                                copy_string(args->b1_args.cskey.script_file,
                                            tempLen,
                                            cur_node->children->content);
                            }
                        }
                        else
                        {
                            fprintf(stderr,
                                    "%s%s and %s cannot be assigned to the "
                                    "same %s, line: %d. Check XML Syntax\n",
                                    getErr(), ELEMENT_SCRIPT, ELEMENT_SIGNKEY,
                                    ELEMENT_CSKEY, cur_node->line);
                            healthy = 0;
                        }
                    }
                }
                else if (checkBlock(cur_node->parent, ELEMENT_B0SIG))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.b0sig.sign_key == NULL)
                        {
                            if (args->b1_args.b0sig.script_file != NULL)
                            {
                                fprintf(stderr,
                                        "%s%s %s has a duplicate argument, "
                                        "line: %d. Check XML syntax.\n",
                                        getErr(), ELEMENT_B0SIG, ELEMENT_SCRIPT,
                                        cur_node->line);
                                healthy = 0;
                            }
                            else
                            {
                                tempLen =
                                    strlen(
                                        (char *)(cur_node->children->content)) +
                                    1;
                                args->b1_args.b0sig.script_file =
                                    malloc(tempLen * sizeof(char));
                                copy_string(args->b1_args.b0sig.script_file,
                                            tempLen,
                                            cur_node->children->content);
                            }
                        }
                        else
                        {
                            fprintf(stderr,
                                    "%s%s and %s cannot be assigned to the "
                                    "same %s, line: %d. Check XML Syntax\n",
                                    getErr(), ELEMENT_SCRIPT, ELEMENT_SIGNKEY,
                                    ELEMENT_B0SIG, cur_node->line);
                            healthy = 0;
                        }
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s%s was unexpected, line: %d. Check XML Syntax\n",
                            getErr(), ELEMENT_SCRIPT, cur_node->line);
                    healthy = 0;
                }
            }
            // Handle Hash Alg
            else if (checkBlock(cur_node, ELEMENT_HASHALG) && healthy)
            {
                if (checkBlock(cur_node->parent, ELEMENT_CSKEY))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.cskey.hashalg != UINT16_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_CSKEY, ELEMENT_HASHALG,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setHashAlg(&(args->b1_args.cskey.hashalg),
                                                 cur_node->children->content,
                                                 cur_node->line);
                        }
                    }
                }
                else if (checkBlock(cur_node->parent, ELEMENT_B0SIG))
                {
                    if (cur_node->children->content != NULL)
                    {
                        if (args->b1_args.b0sig.hashalg != UINT16_MAX)
                        {
                            fprintf(stderr,
                                    "%s%s %s has a duplicate argument, line: "
                                    "%d. Check XML syntax.\n",
                                    getErr(), ELEMENT_B0SIG, ELEMENT_HASHALG,
                                    cur_node->line);
                            healthy = 0;
                        }
                        else
                        {
                            healthy = setHashAlg(&(args->b1_args.b0sig.hashalg),
                                                 cur_node->children->content,
                                                 cur_node->line);
                        }
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s%s was unexpected, line: %d. Check XML Syntax\n",
                            getErr(), ELEMENT_HASHALG, cur_node->line);
                    healthy = 0;
                }
            }

            else if (checkBlock(cur_node, ELEMENT_BLOCKPAD) && healthy)
            {
                if (checkBlock(cur_node->parent, ELEMENT_PADDING))
                {
                    if (args->blockpad != UINT32_MAX)
                    {
                        fprintf(stderr,
                                "%s%s %s has a duplicate argument, line: %d. "
                                "Check XML syntax.\n",
                                getErr(), ELEMENT_PADDING, ELEMENT_BLOCKPAD,
                                cur_node->line);
                        healthy = 0;
                    }
                    else
                    {
                        healthy = setUint32Dec(&(args->blockpad),
                                               cur_node->children->content,
                                               cur_node->line);
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s%s was unexpected, line: %d. Check XML Syntax\n",
                            getErr(), ELEMENT_BLOCKPAD, cur_node->line);
                    healthy = 0;
                }
            }

            else if (checkBlock(cur_node, ELEMENT_ALIGN) && healthy)
            {
                if (checkBlock(cur_node->parent, ELEMENT_PADDING))
                {
                    if (args->align != UINT32_MAX)
                    {
                        fprintf(stderr,
                                "%s%s %s has a duplicate argument, line: %d. "
                                "Check XML syntax.\n",
                                getErr(), ELEMENT_PADDING, ELEMENT_ALIGN,
                                cur_node->line);
                        healthy = 0;
                    }
                    else
                    {
                        healthy = setUint32Dec(&(args->align),
                                               cur_node->children->content,
                                               cur_node->line);
                    }
                }
                else
                {
                    fprintf(stderr,
                            "%s%s was unexpected, line: %d. Check XML Syntax\n",
                            getErr(), ELEMENT_ALIGN, cur_node->line);
                    healthy = 0;
                }
            }

            else if (checkBlock(cur_node, ELEMENT_PADDING))
            {
                if (padding_set)
                {
                    fprintf(stderr,
                            "%sDuplicate %s element at line: %d. Check XML "
                            "syntax.\n",
                            getErr(), ELEMENT_PADDING, cur_node->line);
                    healthy = 0;
                }
                else
                {
                    padding_set = 1;
                }
            }

            else if (checkBlock(cur_node, ELEMENT_VERSION))
            {
                if (checkBlock(cur_node->parent, ELEMENT_BLOCKSIGN))
                {
                    if (args->version != UINT8_MAX)
                    {
                        fprintf(stderr,
                                "%sDuplicate %s element at line: %d. Check XML "
                                "syntax.\n",
                                getErr(), ELEMENT_VERSION, cur_node->line);
                        healthy = 0;
                    }
                    else
                    {
                        healthy = setUint8Dec(&(args->version),
                                              cur_node->children->content,
                                              cur_node->line);
                    }
                }
                else
                {
                    fprintf(
                        stderr,
                        "%s%s was unexpected, line: %d. Check XML Syntax.\n",
                        getErr(), ELEMENT_VERSION, cur_node->line);
                }
            }

            else if (checkBlock(cur_node, ELEMENT_CPLD))
            {
                if (!checkBlock(cur_node->parent, ELEMENT_BLOCKSIGN))
                {
                    fprintf(
                        stderr,
                        "%s%s Was unexpected, line: %d. Check XML Syntax.\n",
                        getErr(), ELEMENT_CPLD, cur_node->line);
                    healthy = 0;
                }
            }

            else if (checkBlock(cur_node, ELEMENT_BYTESWAP))
            {
                if (checkBlock(cur_node->parent, ELEMENT_CPLD))
                {
                    if (args->swapbytes != UINT8_MAX)
                    {
                        fprintf(stderr,
                                "%sDuplicate %s element at line: %d. Check XML "
                                "syntax.\n",
                                getErr(), ELEMENT_BYTESWAP, cur_node->line);
                        healthy = 0;
                    }
                    else
                    {
                        healthy = setTrueFalse(&(args->swapbytes),
                                               cur_node->children->content,
                                               cur_node->line);
                    }
                }
                else
                {
                    fprintf(
                        stderr,
                        "%s%s was unexpected, line: %d. Check XML Syntax.\n",
                        getErr(), ELEMENT_BYTESWAP, cur_node->line);
                    healthy = 0;
                }
            }

            else if (checkBlock(cur_node, ELEMENT_CPLDSVN))
            {
                if (checkBlock(cur_node->parent, ELEMENT_CPLD))
                {
                    if (args->svn != UINT32_MAX)
                    {
                        fprintf(stderr,
                                "%sDuplicate %s element at line: %d. Check XML "
                                "syntax.\n",
                                getErr(), ELEMENT_CPLDSVN, cur_node->line);
                        healthy = 0;
                    }
                    else
                    {
                        healthy = setUint32Dec(&(args->svn),
                                               cur_node->children->content,
                                               cur_node->line);
                    }
                }
                else
                {
                    fprintf(
                        stderr,
                        "%s%s was unexpected, line: %d. Check XML Syntax.\n",
                        getErr(), ELEMENT_CPLDSVN, cur_node->line);
                    healthy = 0;
                }
            }

            // Negative checks
            else if (checkBlock(cur_node, ELEMENT_CSKEY))
            {
                if (!checkBlock(cur_node->parent, ELEMENT_BLOCK1))
                {
                    fprintf(stderr,
                            "%s%s attribute can only reside within BLOCK1. "
                            "Check XML syntax.\n",
                            getErr(), ELEMENT_CSKEY);
                    healthy = 0;
                }
                else if (cskey_set)
                {
                    fprintf(stderr,
                            "%sDuplicate %s element at line: %d. Check XML "
                            "syntax.\n",
                            getErr(), ELEMENT_CSKEY, cur_node->line);
                    healthy = 0;
                }
                else
                {
                    cskey_set = 1;
                }
            }

            else if (checkBlock(cur_node, ELEMENT_B0SIG))
            {
                if (!checkBlock(cur_node->parent, ELEMENT_BLOCK1))
                {
                    fprintf(stderr,
                            "%s%s attribute can only reside within BLOCK1. "
                            "Check XML syntax.\n",
                            getErr(), ELEMENT_B0SIG);
                    healthy = 0;
                }
                else if (b0sig_set)
                {
                    fprintf(stderr,
                            "%sDuplicate %s element at line: %d. Check XML "
                            "syntax.\n",
                            getErr(), ELEMENT_B0SIG, cur_node->line);
                    healthy = 0;
                }
                else
                {
                    b0sig_set = 1;
                }
            }

            else if (checkBlock(cur_node, ELEMENT_RKEY))
            {
                if (!checkBlock(cur_node->parent, ELEMENT_BLOCK1))
                {
                    fprintf(stderr,
                            "%sRKEY attribute can only reside within BLOCK1. "
                            "Check XML syntax.\n",
                            getErr());
                    healthy = 0;
                }
                else if (rootkey_set)
                {
                    fprintf(stderr,
                            "%sDuplicate %s element at line: %d. Check XML "
                            "syntax.\n",
                            getErr(), ELEMENT_RKEY, cur_node->line);
                    healthy = 0;
                }
                else
                {
                    rootkey_set = 1;
                }
            }
            else if (checkBlock(cur_node, ELEMENT_BLOCK0))
            {
                if (block0_set)
                {
                    fprintf(stderr,
                            "%sDuplicate %s element at line: %d. Check XML "
                            "syntax.\n",
                            getErr(), ELEMENT_BLOCK0, cur_node->line);
                    healthy = 0;
                }
                else
                {
                    block0_set = 1;
                }
            }
            else if (checkBlock(cur_node, ELEMENT_BLOCK1))
            {
                if (block1_set)
                {
                    fprintf(stderr,
                            "%sDuplicate %s element at line: %d. Check XML "
                            "syntax.\n",
                            getErr(), ELEMENT_BLOCK1, cur_node->line);
                    healthy = 0;
                }
                else
                {
                    block1_set = 1;
                }
            }

            // fall through
            else if (cur_node->type == XML_ELEMENT_NODE)
            {
                // double check
                if (checkBlock(cur_node, ELEMENT_BLOCKSIGN) ||
                    checkBlock(cur_node, ELEMENT_BLOCK1) ||
                    checkBlock(cur_node, ELEMENT_BLOCK0) ||
                    checkBlock(cur_node, ELEMENT_B0SIG) ||
                    checkBlock(cur_node, ELEMENT_SIGMAGIC) ||
                    checkBlock(cur_node, ELEMENT_MAGIC) ||
                    checkBlock(cur_node, ELEMENT_PCTYPE) ||
                    checkBlock(cur_node, ELEMENT_RKEY) ||
                    checkBlock(cur_node, ELEMENT_CSKEY) ||
                    checkBlock(cur_node, ELEMENT_PERMISSIONS) ||
                    checkBlock(cur_node, ELEMENT_KEYID) ||
                    checkBlock(cur_node, ELEMENT_PUBKEY) ||
                    checkBlock(cur_node, ELEMENT_CURVEMAGIC) ||
                    checkBlock(cur_node, ELEMENT_HASHALG) ||
                    checkBlock(cur_node, ELEMENT_SIGNKEY) ||
                    checkBlock(cur_node, ELEMENT_SCRIPT) ||
                    checkBlock(cur_node, ELEMENT_PADDING) ||
                    checkBlock(cur_node, ELEMENT_BLOCKPAD) ||
                    checkBlock(cur_node, ELEMENT_ALIGN))
                {
                    fprintf(
                        stderr,
                        "%sUnpopulated parameter: %s @ line #%d, ignoring\n",
                        getWrn(), cur_node->name, cur_node->line);
                }
                else
                {
                    fprintf(stderr,
                            "%sUnknown XML element \"%s\" at line: %d. Check "
                            "XML syntax.\n",
                            getErr(), cur_node->name, cur_node->line);
                    healthy = 0;
                }
            }

            if (healthy)
            {
                healthy = parseElements(cur_node, args);
            }
        }
    }
    // if abort is set to 1, this will fall out of call stack, and notify
    // failure
    return healthy;
}

/// Ensure everything is set correctly
int sanityCheck(ARGUMENTS *args)
{
    int ret = 1;
    if (args->version == UINT8_MAX)
    {
        fprintf(stderr, "%s%s is not set. Check XML\n", getErr(),
                ELEMENT_VERSION);
        ret = 0;
    }
    else if (args->version > EXPECT_VERSION)
    {
        fprintf(stderr,
                "%s%s version (%d) is newer than tool version (%d). Please "
                "update your tool to the latest version.\n",
                getErr(), ELEMENT_VERSION, args->version, EXPECT_VERSION);
        ret = 0;
    }
    else if (args->version < EXPECT_VERSION)
    {
        fprintf(stderr,
                "%s%s version (%d) is older than the tool version (%d). Please "
                "recreate your config file with the latest Blockconfig tool.\n",
                getErr(), ELEMENT_VERSION, args->version, EXPECT_VERSION);
        ret = 0;
    }
    if (args->b0_args.magic == UINT32_MAX)
    {
        fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                ELEMENT_BLOCK0, ELEMENT_MAGIC);
        ret = 0;
    }
    if (args->b0_args.pctype == UINT32_MAX)
    {
        fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                ELEMENT_BLOCK0, ELEMENT_PCTYPE);
        ret = 0;
    }
    if (args->b1_args.magic == UINT32_MAX)
    {
        fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                ELEMENT_BLOCK1, ELEMENT_MAGIC);
        ret = 0;
    }
    if (args->b1_args.root_key.curve_magic == UINT32_MAX)
    {
        fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                ELEMENT_RKEY, ELEMENT_CURVEMAGIC);
        ret = 0;
    }
    if (args->b1_args.root_key.keyid == INT32_MAX)
    {
        fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                ELEMENT_RKEY, ELEMENT_KEYID);
        ret = 0;
    }
    if (args->b1_args.root_key.magic == UINT32_MAX)
    {
        fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                ELEMENT_RKEY, ELEMENT_MAGIC);
        ret = 0;
    }
    if (args->b1_args.root_key.permissions == INT32_MAX)
    {
        fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                ELEMENT_RKEY, ELEMENT_PERMISSIONS);
        ret = 0;
    }
    if (args->b1_args.root_key.pubkey == NULL)
    {
        fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                ELEMENT_RKEY, ELEMENT_PUBKEY);
        ret = 0;
    }

    if (cskey_set)
    {
        if (args->b1_args.cskey.curve_magic == UINT32_MAX &&
            args->b0_args.pctype != 0)
        {
            fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                    ELEMENT_CSKEY, ELEMENT_CURVEMAGIC);
            ret = 0;
        }
        if (args->b1_args.cskey.hashalg == UINT16_MAX &&
            args->b0_args.pctype != 0)
        {
            fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                    ELEMENT_CSKEY, ELEMENT_HASHALG);
            ret = 0;
        }
        if (args->b1_args.cskey.keyid == INT32_MAX && args->b0_args.pctype != 0)
        {
            fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                    ELEMENT_CSKEY, ELEMENT_KEYID);
            ret = 0;
        }
        if (args->b1_args.cskey.magic == UINT32_MAX &&
            args->b0_args.pctype != 0)
        {
            fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                    ELEMENT_CSKEY, ELEMENT_MAGIC);
            ret = 0;
        }
        if (args->b1_args.cskey.permissions == INT32_MAX &&
            args->b0_args.pctype != 0)
        {
            fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                    ELEMENT_CSKEY, ELEMENT_PERMISSIONS);
            ret = 0;
        }
        if (args->b1_args.cskey.pubkey == NULL && args->b0_args.pctype != 0)
        {
            fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                    ELEMENT_CSKEY, ELEMENT_PUBKEY);
            ret = 0;
        }
        if (args->b1_args.cskey.sig_magic == UINT32_MAX &&
            args->b0_args.pctype != 0)
        {
            fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                    ELEMENT_CSKEY, ELEMENT_SIGMAGIC);
            ret = 0;
        }
        if (args->b1_args.cskey.script_file == NULL &&
            args->b1_args.cskey.sign_key == NULL && args->b0_args.pctype != 0)
        {
            fprintf(stderr,
                    "%s%s must have either %s OR %s set to perform signing. "
                    "Check XML\n",
                    getErr(), ELEMENT_CSKEY, ELEMENT_SIGNKEY, ELEMENT_SCRIPT);
            ret = 0;
        }
    }
    else
    {
        fprintf(stderr,
                "%s%s is not present in XML, setting certificate cancellation "
                "bit.\n",
                getWrn(), ELEMENT_CSKEY);
        args->b0_args.pctype += CANCELLATION_BIT;
    }
    if (args->b1_args.b0sig.hashalg == UINT16_MAX)
    {
        fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                ELEMENT_B0SIG, ELEMENT_HASHALG);
        ret = 0;
    }
    if (args->b1_args.b0sig.magic == UINT32_MAX)
    {
        fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                ELEMENT_B0SIG, ELEMENT_MAGIC);
        ret = 0;
    }
    if (args->b1_args.b0sig.sig_magic == UINT32_MAX)
    {
        fprintf(stderr, "%s%s %s is not set. Check XML\n", getErr(),
                ELEMENT_B0SIG, ELEMENT_SIGMAGIC);
        ret = 0;
    }
    if (args->b1_args.b0sig.script_file == NULL &&
        args->b1_args.b0sig.sign_key == NULL)
    {
        fprintf(stderr,
                "%s%s must have either %s OR %s set to perform signing. Check "
                "XML\n",
                getErr(), ELEMENT_B0SIG, ELEMENT_SIGNKEY, ELEMENT_SCRIPT);
        ret = 0;
    }
    return ret;
}

/// Initializes XML parser engine, and kicks off recursive function
int parseArgs(const char *xmlFile, ARGUMENTS *args)
{
    int ret = 1;

    xmlDocPtr doc; /* the resulting document tree */
    xmlNode *root_element = NULL;

    if (args->verbose)
    {
        printf("%sEnsuring XML syntax is correct.\n", getNfo());
    }
    doc = xmlReadFile(xmlFile, NULL, 0);
    if (doc == NULL)
    {
        fprintf(stderr, "Failed to parse %s\n", xmlFile);
        ret = 0;
    }
    if (ret)
    {
        /*Get the root element node */
        root_element = xmlDocGetRootElement(doc);
        /*Before recursive call, check root element*/
        if (!checkBlock(root_element, ELEMENT_BLOCKSIGN))
        {
            fprintf(
                stderr,
                "%sUnknown XML element \"%s\" at line: %d. Check XML syntax.\n",
                getErr(), root_element->name, root_element->line);
            ret = 0;
        }
        else
        {
            if (args->verbose)
            {
                printf(
                    "%sRecursively parsing XML tree and checking semantics.\n",
                    getNfo());
            }
            ret = parseElements(root_element, args);
        }
        if (!ret)
        {
            fprintf(stderr, "%sFailure occurred when reading in XML elements\n",
                    getErr());
        }
        else
        {
            if (args->verbose)
            {
                printf("%sOne last sanity check to make sure all necessary "
                       "args have been populated.\n",
                       getNfo());
            }
            ret = sanityCheck(args);
        }
        xmlFreeDoc(doc);
        xmlCleanupParser();
    }

    return ret;
}

/// Prints the usage information
void printUsage()
{
    printf("%sExample build: intel-pfr-signing-utility -c config.xml -o output.bin input.bin "
           "[-v]\n",
           getNfo());
    printf("%sExample parse: intel-pfr-signing-utility -p output.bin [-c config.xml]\n",
           getNfo());
}
int setParse = 0;
int setXml = 0;
int setOutput = 0;
int setInput = 0;
int parseCli(int argc, char **argv, ARGUMENTS *args)
{
    char *xmlFile = NULL;
    int ret = 1;
    int i;
    int tempLen;
    if (argc == 1)
    {
        ret = 0;
    }
    else
    {
        for (i = 1; i < argc && ret; ++i)
        {
            if (strcmp(argv[i], CLI_PARSE) == 0)
            {
                if (setParse)
                {
                    fprintf(stderr,
                            "%sDuplicate parse flags '-p' on the commandline.",
                            getErr());
                    ret = 0;
                }
                else
                {
                    setParse = 1;
                    args->parse = 1;
                }
            }
            else if (strcmp(argv[i], CLI_CONFIG) == 0)
            {
                if (setXml)
                {
                    fprintf(stderr,
                            "%sDuplicate config flags '-c' on the commandline.",
                            getErr());
                    ret = 0;
                }
                else if (xmlFile != NULL)
                {
                    fprintf(stderr,
                            "%sDuplicate config flags '-c' on the commandline.",
                            getErr());
                    ret = 0;
                }
                else
                {
                    setXml = 1;
                }
            }
            else if (strcmp(argv[i], CLI_OUTPUT) == 0)
            {
                if (setOutput)
                {
                    fprintf(stderr,
                            "%sDuplicate output flags '-o' on the commandline.",
                            getErr());
                    ret = 0;
                }
                else if (args->outputBinary != NULL)
                {
                    fprintf(stderr,
                            "%sDuplicate output flags '-o' on the commandline.",
                            getErr());
                    ret = 0;
                }
                else
                {
                    setOutput = 1;
                }
            }
            else if (strcmp(argv[i], CLI_VERBOSE) == 0)
            {
                if (!(args->verbose))
                {
                    args->verbose = 1;
                }
                else
                {
                    fprintf(
                        stderr,
                        "%sDuplicate verbose flags '-v' on the commandline.",
                        getErr());
                }
            }
            else if (setXml)
            {
                // unnecessary check
                if (xmlFile == NULL)
                {
                    tempLen = (strlen(argv[i]) + 1);
                    xmlFile = malloc(tempLen * sizeof(char));
                    copy_string(xmlFile, tempLen, argv[i]);
                    setXml = 0;
                }
            }
            else if (setOutput)
            {
                // unnecessary check
                if (args->outputBinary == NULL)
                {
                    /*tempLen = (strlen(argv[i]) + 1);
                    args->outputBinary = malloc(tempLen * sizeof(char));
                    copy_string(args->outputBinary, tempLen, argv[i]);*/
#ifdef _WIN32
                    args->outputBinary = malloc(sizeof(char) * _MAX_PATH);
                    _fullpath(args->outputBinary, argv[i], _MAX_PATH);
#else

                    // HACK
                    // I know this is hacky, but realpath() was giving me all
                    // kinds of problems.
                    char current[PATH_MAX];
                    if (argv[i][0] != '/')
                    {
                        if (getcwd(current, sizeof(current)) != NULL)
                        {
                            int tempLen = strlen(current) + strlen(argv[i]) +
                                          2; // one for slash one for NULL term
                            args->outputBinary = malloc(sizeof(char) * tempLen);
                            copy_string(args->outputBinary, tempLen, current);
                            cat_string(args->outputBinary, tempLen, "/");
                            cat_string(args->outputBinary, tempLen, argv[i]);
                        }
                    }
                    else
                    {
                        // absolute path
                        tempLen = strlen(argv[i]) + 1;
                        args->outputBinary = malloc(sizeof(char) * tempLen);
                        copy_string(args->outputBinary, tempLen, argv[i]);
                    }
#endif
                    setOutput = 0;
                }
            }
            else
            {
                if (argv[i][0] == '-')
                {
                    fprintf(stderr, "%sUnknown flag: %s\n", getErr(), argv[i]);
                    ret = 0;
                }
                else
                {
                    if (args->inputBinary != NULL)
                    {
                        fprintf(stderr, "%sDuplicate input binary specified\n",
                                getErr());
                        ret = 0;
                    }
                    else
                    {
                        /*tempLen = (strlen(argv[i]) + 1);
                        args->inputBinary = malloc(tempLen * sizeof(char));
                        copy_string(args->inputBinary, tempLen, argv[i]);*/
#ifdef _WIN32
                        args->inputBinary = malloc(sizeof(char) * _MAX_PATH);
                        _fullpath(args->inputBinary, argv[i], _MAX_PATH);
#else
                        // HACK
                        // I know this is hacky, but realpath() was giving me
                        // all kinds of problems.
                        char current[PATH_MAX];
                        if (argv[i][0] != '/')
                        {
                            if (getcwd(current, sizeof(current)) != NULL)
                            {
                                int tempLen =
                                    strlen(current) + strlen(argv[i]) +
                                    2; // one for slash one for NULL term
                                args->inputBinary =
                                    malloc(sizeof(char) * tempLen);
                                copy_string(args->inputBinary, tempLen,
                                            current);
                                cat_string(args->inputBinary, tempLen, "/");
                                cat_string(args->inputBinary, tempLen, argv[i]);
                            }
                        }
                        else
                        {
                            // absolute path
                            tempLen = strlen(argv[i]) + 1;
                            args->inputBinary = malloc(sizeof(char) * tempLen);
                            copy_string(args->inputBinary, tempLen, argv[i]);
                        }
#endif
                    }
                }
            }
        }
    }
    // sanitize input
    if (setParse && (setOutput || setXml || args->outputBinary != NULL))
    {
        fprintf(stderr, "%sAmbiguous CLI parameters\n", getErr());
        ret = 0;
    }
    if (setParse && args->inputBinary == NULL)
    {
        fprintf(stderr, "%sInput binary must be specified for parsing\n",
                getErr());
        ret = 0;
    }
    if (!setParse && (args->inputBinary == NULL || args->outputBinary == NULL ||
                      xmlFile == NULL))
    {
        // forgot to specify something.
        ret = 0;
    }
    if (args->inputBinary != NULL && args->outputBinary != NULL &&
        strcmp(args->inputBinary, args->outputBinary) == 0)
    {
        fprintf(stderr, "%sInput and Output file cannot be the same.\n",
                getErr());
        ret = 0;
    }
    if (!ret)
    {
        if (xmlFile != NULL)
        {
            free(xmlFile);
            xmlFile = NULL;
        }
        printUsage();
    }
    else if (xmlFile != NULL)
    {
        ret = parseArgs(xmlFile, args);
        if (ret)
        {
            if (truncateFilePath(xmlFile))
            {
#ifdef _WIN32
                _chdir(xmlFile);
#else
                ret = !(chdir(xmlFile));
#endif
            }
        }
        free(xmlFile);
        if (ret && args->verbose)
        {
            printf("%sSuccessfully parsed XML and populated arguments.\n",
                   getNfo());
        }
    }
    return ret;
}
