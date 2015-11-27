
#include <iostream>
#include "cryp.h"

using namespace cryp;


void test_str()
{
    const char* name = "HTTP_ACCEPT";

    const char* http = strstr(name, "HTTP_");
    if (http)
    {
        printf("http=%p  found=%d  restofname='%s'\n", http, name == http, name + 5);
    }

    printf("---\n");
    for (char** envp = environ; *envp; ++envp)
    {
        const char* fld = *envp;

        char name[128];
        const char* value = NULL;
        const char* eq = strchr(fld, '=');
        if (eq)
        {
            uint namelen = eq - fld;
            if (namelen < (sizeof(name) - 1))
            {
                memcpy(name, fld, namelen);
                name[namelen] = '\0';
                value = eq + 1;

                printf("name='%s'\nvalue='%s'\n", name, value);

                const char* http = strstr(name, "HTTP_");
                if (http)
                {
                    printf("http=%p  found=%d  restofname='%s'\n", http, name == http, name + 5);
                }

            }
        }
    }
}

void test_replace()
{
    std::string s = "this is a string with a  bunch  of spaces.  And ? : ; ?? weird stuff";

    printf("%s\n", s.c_str());

    replaceAll(s, " ", "__");

    printf("%s\n", s.c_str());

    replaceAll(s, "__", ",");

    printf("%s\n", s.c_str());
}



void test_spliter_helper(const char* txt)
{
    printf("split:'%s'\n", txt);

    Splitter semisplt(txt, ";");
    while (!semisplt.eof())
    {
        std::string frag = semisplt.get();
        Splitter splt(frag.c_str(), "=");

        printf("'%s'\n", frag.c_str());
        while (!splt.eof())
        {
            printf("   '%s'\n", splt.get().c_str());
        }
        printf("\n");
    }
    printf("\n");
}


void test_spliter()
{
    const char* cookie1 =
        "datr=diF4VLoekyAx0jH3sC5Zt-bh; expires=Sun, 27-Nov-2016 07:17:10 GMT; Max-Age=63072000; path=/; domain=.facebook.com; httponly";
    const char* cookie2 =
        "reg_ext_ref=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; domain=.facebook.com";
    const char* cookie3 = "reg_fb_ref=https%3A%2F%2Fwww.facebook.com%2F; path=/; domain=.facebook.com";
    const char* cookie4 = "reg_fb_gate=https%3A%2F%2Fwww.facebook.com%2F; path=/; domain=.facebook.com";
    const char* cookie5 = "testsingle";

    test_spliter_helper(cookie1);
    test_spliter_helper(cookie2);
    test_spliter_helper(cookie3);
    test_spliter_helper(cookie4);
    test_spliter_helper(cookie5);

}


void test_time()
{
    Date d;
    Date d2;

    d2.now();

    printf("d1= [%s]\n", d.toString().c_str());

    d.tm_mday += 30;
    d.normalize();

    printf("d1= [%s]\n", d.toString().c_str());

    printf("d2= [%s] %ld\n", d2.toString().c_str(), d2.utc());

    Date d3(d2.utc());

    printf("d3= [%s] %ld\n", d3.toString().c_str(), d3.utc());

    d3.tm_min += 4;

    printf("diff %ld seconds", d3.secondsSince(d2));
}



void test_md5()
{
    DigestMd5 dig;
    const char* string = "happy\n";

    printf("Digestmd5 digest: %s\n", dig.toHexString().c_str());

    dig.update(string, strlen(string));

    printf("Digestmd5 digest: %s\n", dig.toHexString().c_str());

    dig.clear();
    printf("Digestmd5 digest: %s\n", dig.toHexString().c_str());

    dig.update(string);

    printf("Digestmd5 digest: %s\n", dig.toHexString().c_str());
}



void test_base64()
{

    const std::string s =
        "ADP GmbH\nAnalyse Design & Programmierung\nGesellschaft mit beschränkter Haftung" ;

    // std::string encoded = base64_encode(reinterpret_cast<const unsigned char*>(s.c_str()), s.length());
    // std::string decoded = base64_decode(encoded);

    std::string encoded = Base64::encode(s.c_str());

    std::string decoded = Base64::decode(encoded);


    std::cout << "encoded: " << encoded << std::endl;
    std::cout << "decoded: " << decoded << std::endl;
}

void test_dir()
{
    printf("path:%s\n", pathThisProc().c_str());
    printf("path:%s\n", pathThisProc("test/name/a.txt").c_str());
    printf("path:%s\n", pathThisProc("config.json").c_str());
}


void test_bcrypt()
{
    PwdHash ph;
    std::string hash;

    const char* password = "yasser";

    printf("Creating hash for password: %s\n", password);
    ph.createHash(password, hash);

    printf("hash'%s'\n", hash.c_str());

    printf("\nValidating password: %s\n", password);
    ph.validatePassword(password, hash);

    password = "Yasser";
    printf("\nValidating password: %s\n", password);
    ph.validatePassword(password, hash);

    password = "Asmi";
    printf("\nValidating password: %s\n", password);
    ph.validatePassword(password, hash);

}

void test_hmac()
{
    //HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog") = 0xf7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8

    std::cout << "should be: f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8" << std::endl;
//    std::cout << "hmacHex  : " << hmacHex("key", "The quick brown fox jumps over the lazy dog") << std::endl;
//    std::cout << "binary   : " << hmac("key", "The quick brown fox jumps over the lazy dog") << std::endl;

    Hmac hm;
    hm.createSha256("key");
    hm.update("The quick brown fox jumps over the lazy dog");
    std::cout << "class_hex: " << hm.toHexString() << std::endl;
    std::cout << "class_bin: " << hm.toBinString() << std::endl;

    std::string b64 = hm.toB64String();
    Base64::trimPadding(b64);
    std::cout << "class_b64: " << b64 << std::endl;

}


void test_strbld()
{
    StrBld sb;
    StrBld sb2("This is interesting way to build a string#");

    sb.append('y');
    sb.append('a');
    sb.append('s');
    sb.append('s');
    sb.append('e');
    sb.append('r');

    sb.append(" asmi.");


    printf("sb:[%s]   sb2:[%s]\n", sb.c_str(), sb2.c_str());

    printf("cmp=%d  eq=%d\n", sb.compare("yasser asmi."), sb.equals("yasser asmi."));

    sb.replaceLast('!');

    printf("cmp=%d  eq=%d\n", sb.compare("yasser asmi."), sb.equals("yasser asmi."));

    sb2.eraseLast();

    printf("sb:[%s]   sb2:[%s]\n", sb.c_str(), sb2.c_str());

    sb.append(sb2);
    sb.append(sb2);
    sb.append(sb2);
    sb.append(sb2);
    printf("sb:[%s]   sb2:[%s]\n", sb.c_str(), sb2.c_str());


    sb2.clear();
    sb2.append("\"Hello world\"");

    sb.clear();
    sb.append("'this is cool'");

    printf("sb:[%s]   sb2:[%s]\n", sb.c_str(), sb2.c_str());

    sb.stripQuotes(true);
    sb2.stripQuotes(true);
    printf("sb:[%s]   sb2:[%s]\n", sb.c_str(), sb2.c_str());

    sb.clear();
    sb.stripQuotes(true);
    sb2.stripQuotes(true);
    printf("sb:[%s]   sb2:[%s]\n", sb.c_str(), sb2.c_str());

    sb.appendFmt(" (%d %s)", 20, "days");
    sb2.appendFmt("  %lf  ", 22.33);
    printf("sb:[%s]   sb2:[%s]\n", sb.c_str(), sb2.c_str());
}

int main(int argc, char** argv)
{
    test_md5();
    test_bcrypt();
    test_hmac();
    test_base64();
    test_spliter();
    test_time();
    test_replace();
    test_str();
    test_strbld();
}

