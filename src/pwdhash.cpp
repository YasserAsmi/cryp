// Copyright (c) 2014 Yasser Asmi
// Released under the MIT License (http://opensource.org/licenses/MIT)

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "cryp.h"

namespace cryp
{

// Reference: https://crackstation.net/hashing-security.htm

PwdHash::PwdHash()
{
}

bool PwdHash::createHash(const std::string& password, std::string& genhash)
{
    genhash.clear();

    // Generate random salt.

    unsigned char salt[PH_SALT_BYTE_SIZE];
    if (!RAND_bytes(salt, sizeof(salt)))
    {
        dbgerr("Failed to generate salt\n");
        return false;
    }
    dbghex("salt", salt, sizeof(salt));

    // Generate the hash.

    Buffer hash(sizeof(unsigned char) * PH_KEY_LEN);

    if (!PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(), salt, sizeof(salt),
        PH_PBKDF2_ITERATIONS, hash.size(), (unsigned char*)hash.ptr()) != 0)
    {
        dbgerr("PBKDF2 failed\n");
        return false;
    }
    dbghex(">>Pwd->hash", hash.cptr(), hash.size());

    // Build the combined string with iteration count, base 64 encoded salt, and base 64 encoded hash

    format(genhash, "%d:%s:%s", PH_PBKDF2_ITERATIONS,
        Base64::encode(salt, sizeof(salt)).c_str(),
        Base64::encode((const unsigned char*)hash.cptr(), hash.size()).c_str());

    return true;
}

bool PwdHash::validatePassword(const std::string& password, const std::string& correcthash)
{
    // Extract parameters from the correct hash

    Splitter splt(correcthash.c_str(), ":");
    int iterations = str2int(splt.get());
    std::string saltbytes = Base64::decode(splt.get());
    std::string correcthashbytes = Base64::decode(splt.get());

    //dbglog("iter=%d \n", iterations);
    //dbghex("correct salt", saltbytes.c_str(), saltbytes.size());
    //dbghex(">>Correct hash", correcthashbytes.c_str(), correcthashbytes.size());

    // Calculate new test hash using the provided password, extracted salt, and extracted iteration count

    Buffer testhash(sizeof(unsigned char) * PH_KEY_LEN);
    if (!PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(),
        (unsigned char*)saltbytes.c_str(), saltbytes.size(),
        iterations, testhash.size(), (unsigned char*)testhash.ptr()) != 0)
    {
        dbgerr("PBKDF2 failed\n");
        return false;
    }

    dbghex(">>Calc hash", testhash.cptr(), testhash.size());

    // Compare the two hashes with constant time compare function.

    if (!constantTimeEquals((const unsigned char*)correcthashbytes.c_str(), correcthashbytes.size(),
        (const unsigned char*)testhash.cptr(), testhash.size()))
    {
        dbglog(">>Hashes didn't match\n");
        return false;
    }

    // Everything matches/checks out.

    dbglog(">>Hashes matched!!!\n");
    return true;
}


/**
 * To avoid timing attacks, this function performs a constant time compare.
 */
bool PwdHash::constantTimeEquals(const unsigned char* arr1, size_t siz1, const unsigned char* arr2, size_t siz2)
{
    int diff = 0;
    if (siz1 != siz2)
    {
        diff++;
    }
    for (size_t i = 0; i < siz1 && i < siz2; i++)
    {
        if (arr1[i] != arr2[i])
        {
            diff++;
        }
    }
    return diff == 0;
}

}