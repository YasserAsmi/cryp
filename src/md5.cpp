// Copyright (c) 2014 Yasser Asmi
// Released under the MIT License (http://opensource.org/licenses/MIT)

#include <openssl/rand.h>
#include "cryp.h"

namespace cryp
{

std::string mkSessionKey(const std::string& time, const std::string& userinfo)
{
    DigestMd5 dig;
    unsigned char r[8];
    RAND_bytes(r, sizeof(r));

    // add time
    dig.update(time);

    // add random
    dig.update(r, sizeof(r));

    // add user info
    dig.update(userinfo);

    return dig.toHexString();
}

// DigestMd5::

DigestMd5::DigestMd5()
{
    clear();
}

void DigestMd5::clear()
{
    mState = CLEARED;
    MD5_Init(&mCtx);
}

void DigestMd5::update(const void* data, unsigned long len)
{
    if (mState != FINALED)
    {
        (void)MD5_Update(&mCtx, data, len);
        mState = UPDATED;
    }
}

void DigestMd5::update(const std::string& data)
{
    update(data.c_str(), data.length());
}

void DigestMd5::finish()
{
    if (mState == UPDATED)
    {
        MD5_Final(mDigest, &mCtx);
        clear();
        mState = FINALED;
    }
}

std::string DigestMd5::toHexString()
{
    finish();
    if (mState != FINALED)
    {
        return std::string();
    }
    char buf[MD5_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        sprintf(&buf[i * 2], "%02x", (unsigned int)mDigest[i]);
    }
    return std::string(buf, MD5_DIGEST_LENGTH * 2);
}

std::string DigestMd5::toB64String()
{
    finish();
    if (mState != FINALED)
    {
        return std::string();
    }
    return Base64::encode(mDigest, MD5_DIGEST_LENGTH);
}

}