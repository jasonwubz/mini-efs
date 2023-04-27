#ifndef MINIEFS_AUTH
#define MINIEFS_AUTH

#include <cstdlib>
#include <openssl/rsa.h>
#include <vector>
#include <string>

#define AUTH_DIR_PERMISSION 0744
#define AUTH_KEY_TYPE_PUBLIC 1
#define AUTH_KEY_TYPE_PRIVATE 2

namespace auth
{
    extern const std::string AUTH_DIR_FILESYSTEM;
    extern const std::string AUTH_DIR_PUBLICKEYS;
    extern const std::string AUTH_DIR_PRIVATEKEYS;

    struct User{
        bool isAdmin;
        std::string keyName;
        std::string username;
        RSA *publicKey;
        RSA *privateKey;
        void set_user(std::string username, std::string keyName = "");
        RSA *private_key_by_name();
        RSA *get_key(int type);
    };
    bool is_admin(std::string username);

    class AuthException : public std::exception {
        private:
            std::string message;
        public:
            AuthException(std::string msg);
            std::string what();
    };


    std::string csprng();
    std::string hash(std::string name);
    RSA *get_key(int type, std::string path);
    void create_keypair(std::string key_name);
    void save_file(std::string filename, char *content, size_t n);
    int encrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding = RSA_PKCS1_OAEP_PADDING);
    int decrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding = RSA_PKCS1_OAEP_PADDING);
    int authenticate(std::string key_name);
    int initial_setup();
    int user_setup(std::string username);
    int validate(std::string &key_name, auth::User &currentUser);
}

#endif