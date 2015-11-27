// Copyright (c) 2014 Yasser Asmi
// Released under the MIT License (http://opensource.org/licenses/MIT)

#include "cryp.h"

namespace cryp
{


Hmac::Hmac() :
    mLen(0)
{
    HMAC_CTX_init(&mCtx);
}

Hmac::~Hmac()
{
    HMAC_CTX_cleanup(&mCtx);
}

void Hmac::createSha256(const std::string& key)
{
    HMAC_Init_ex(&mCtx, key.c_str(), key.length(), EVP_sha256(), NULL);
    mLen = 0;
}

void Hmac::update(const std::string& data)
{
    update(data.c_str(), data.length());
}

void Hmac::update(const void* data, unsigned long len)
{
    HMAC_Update(&mCtx, (unsigned char*)data, len);
}

void Hmac::finish()
{
    if (mLen == 0)
    {
        mLen = EVP_MAX_MD_SIZE;
        HMAC_Final(&mCtx, mHash, &mLen);
    }
}

std::string Hmac::toHexString()
{
    finish();
    if (mLen == 0)
    {
        return std::string();
    }

    char buf[EVP_MAX_MD_SIZE * 2 + 1];
    for (unsigned int i = 0; i < mLen; i++)
    {
        sprintf(&buf[i * 2], "%02x", (unsigned int)mHash[i]);
    }
    return std::string(buf, mLen * 2);
}

std::string Hmac::toBinString()
{
    finish();
    if (mLen == 0)
    {
        return std::string();
    }

    // TODO: double check this
    return std::string((const char*)mHash, mLen);
}

std::string Hmac::toB64String()
{
    finish();
    if (mLen == 0)
    {
        return std::string();
    }

    return Base64::encode(mHash, mLen);
}

}