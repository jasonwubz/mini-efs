#ifndef MINIIEFS_AUTH
#define MINIIEFS_AUTH

#include <cstdlib>
#include <openssl/rsa.h>
#include <vector>
#include <string>

namespace auth
{
    RSA * read_RSAkey(std::string key_type, std::string key_path);
    //void create_RSA(string key_name);
    int public_encrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding);
    int private_decrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding);
    int login_authentication(std::string key_name);
    //void initial_adminkey_setup();
    std::string sha256_to_name(std::string sha);
    std::string name_to_sha256(std::string name);
}

#endif