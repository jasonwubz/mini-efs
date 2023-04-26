#ifndef MINIIEFS_AUTH
#define MINIIEFS_AUTH

#include <cstdlib>
#include <openssl/rsa.h>
#include <vector>
#include <string>

#define AUTH_DIR_PERMISSION 0744
#define AUTH_KEY_TYPE_PUBLIC 1
#define AUTH_KEY_TYPE_PRIVATE 2

namespace auth
{
    struct User{
        bool isAdmin;
        std::string username;
        RSA *publicKey;
        RSA *privateKey;
        void set_user(std::string username);
        RSA *get_key(int type);
    };
    bool is_admin(std::string username);

    std::string csprng();
    RSA *get_key(int type, std::string path);
    void create_RSA(std::string key_name);
    void create_encrypted_file(std::string filename, char *encrypted_content, RSA *key_pair);
    int public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding = RSA_PKCS1_OAEP_PADDING);
    int private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding = RSA_PKCS1_OAEP_PADDING);
    int login_authentication(std::string key_name);
    int initial_setup();
    int user_folder_setup(std::string new_username);
    std::string hash_to_val(std::string sha);
    std::string hash(std::string name);
}

#endif