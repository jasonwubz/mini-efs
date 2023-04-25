#ifndef MINIIEFS_AUTH
#define MINIIEFS_AUTH

#include <cstdlib>
#include <openssl/rsa.h>
#include <vector>
#include <string>

namespace auth
{
    std::string csprng();
    RSA * read_RSAkey(std::string key_type, std::string key_path);
    void create_RSA(std::string key_name);
    void create_encrypted_file(std::string filename, char* encrypted_content, RSA* key_pair);
    int public_encrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding);
    int private_decrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding);
    int login_authentication(std::string key_name);
    //void initial_adminkey_setup();
    int user_folder_setup(std::string new_username);
    std::string hash_to_val(std::string sha);
    std::string hash(std::string name);
}

#endif