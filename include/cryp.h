// Copyright (c) 2014 Yasser Asmi
// Released under the MIT License (http://opensource.org/licenses/MIT)

#ifndef _CRYP_H
#define _CRYP_H

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <string>
#include <openssl/md5.h>
#include <openssl/hmac.h>

#include "cryputil.h"

// Internal: Use Base64 class instead
std::string base64_encode(unsigned char const* , unsigned int len);
std::string base64_decode(std::string const& s);

namespace cryp
{

std::string mkSessionKey(const std::string& time, const std::string& userinfo);

// DigestMd5::

class DigestMd5
{
public:
    DigestMd5();

    void update(const void* data, unsigned long len);
    void update(const std::string& data);
    void clear();

    std::string toHexString();
    std::string toB64String();

protected:
    enum {
        CLEARED,
        UPDATED,
        FINALED
    } mState;

    MD5_CTX mCtx;
    unsigned char mDigest[MD5_DIGEST_LENGTH];

    void finish();
};

// Base64::

class Base64
{
public:
    /**
     * For a byte array
     */
    static
    std::string encode(const unsigned char* data, unsigned int len)
    {
        return base64_encode((unsigned char const*)data, len);
    }

    /**
     * For a null-terminated string
     */
    static
    std::string encode(const char* str)
    {
        return base64_encode((unsigned char const*)str, strlen(str));
    }

    static
    std::string decode(const std::string& encdata)
    {
        return base64_decode(encdata);
    }

    /**
     * Trims '=' padding chars from a base64 string ending
     */
    static
    void trimPadding(std::string& str)
    {
        size_t i = str.size();
        while (i > 0 && (str[i - 1] == '='))
        {
            i--;
        }
        str.erase(i, str.size());
    }

};

// PwdHash::

class PwdHash
{
public:
    PwdHash();

    bool createHash(const std::string& password, std::string& genhash);
    bool validatePassword(const std::string& password, const std::string& correcthash);

public:
    enum
    {
        PH_KEY_LEN = 20,
        PH_SALT_BYTE_SIZE = 24,
        PH_HASH_BYTE_SIZE = 24,
        PH_PBKDF2_ITERATIONS = 1000,
    };

    static
    bool constantTimeEquals(const unsigned char* arr1, size_t siz1, const unsigned char* arr2, size_t siz2);
};


// Hmac::

class Hmac
{
public:
    Hmac();
    ~Hmac();

    void createSha256(const std::string& key);
    void update(const void* data, unsigned long len);
    void update(const std::string& data);

    std::string toHexString();
    std::string toB64String();
    std::string toBinString();

protected:
    HMAC_CTX mCtx;
    unsigned char mHash[EVP_MAX_MD_SIZE];
    unsigned int mLen;

    void finish();
};


} // namespace cryp


#endif // _CRYP_H