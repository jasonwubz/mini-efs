
#include <auth.h>
#include <metadata.h>
#include <cstdlib>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <sys/stat.h>
#include <jsoncpp/json/json.h>

// Initialize user values
void auth::User::set_user(std::string u)
{
    username = u;
    isAdmin = false;
    if (strcasecmp(username.c_str(), "admin") == 0) {
        isAdmin = true;
    }
}

// Get user's RSA (public or private)
RSA *auth::User::get_key(int type)
{
    std::string path;

    if (type == AUTH_KEY_TYPE_PUBLIC) {
        path = "./publickeys/" + auth::hash(username + "_publickey");
    } else if (type == AUTH_KEY_TYPE_PRIVATE) {
        path = "./privatekeys/" + auth::hash(username);
    }

    if (type == AUTH_KEY_TYPE_PUBLIC) {
        if (publicKey != NULL) {
            return publicKey;
        }
        path = "./publickeys/" + auth::hash(username + "_publickey");
        publicKey = auth::get_key(type, path);
        return publicKey;
    } else if (type == AUTH_KEY_TYPE_PRIVATE) {
        if (privateKey != NULL) {
            return privateKey;
        }
        path = "./privatekeys/" + auth::hash(username);
        privateKey = auth::get_key(type, path);
        return privateKey;
    }

    return NULL;
}

std::string auth::csprng()
{
    constexpr size_t rsize = 32;
    unsigned char ran_buf[rsize];
    std::ostringstream result_stream;

    if (RAND_bytes(ran_buf, rsize) != 1) {
        std::cout << "Error generating random bytes";
        return "";
    }

    for (size_t i = 0; i < rsize; i++) {
        result_stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ran_buf[i]);
    }

    return result_stream.str();
}

bool auth::is_admin(std::string username)
{
    if (strcasecmp(username.c_str(), "admin") == 0) {
        return true;
    }
    return false;
}

// This function implement RSA public key encryption
int auth::encrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding)
{
    return RSA_public_encrypt(flen, from, to, key, padding);
}

// This function implement RSA private key decryption
int auth::decrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding)
{
    return RSA_private_decrypt(flen, from, to, key, padding);
}

// Get RSA (public or private) key specified by path
RSA *auth::get_key(int type, std::string path)
{
    FILE *fp  = NULL;
    RSA *key = NULL;

    fp = fopen(&path[0], "rb");
    if (fp == NULL) {
        return key;
    }

    if (type == AUTH_KEY_TYPE_PUBLIC) {
        PEM_read_RSAPublicKey(fp, &key, NULL, NULL);
        fclose(fp);
    } else if (type == AUTH_KEY_TYPE_PRIVATE) {
        PEM_read_RSAPrivateKey(fp, &key, NULL, NULL);
        fclose(fp);
    }

    return key;
}

void auth::save_file(std::string filename, char *content, size_t n)
{
    FILE *fp = fopen(&filename[0], "wb");
    if (fp == nullptr) {
        std::cout << "Unable to create file, please check directory permissions" << std::endl;
        return;
    }
    fwrite(content, sizeof(*content), n, fp);
    fclose(fp);
}

// SHA-256 hash value of given string
std::string auth::hash(std::string value)
{
    // Append salt before calculating the sha256 hash. Makes dictionary attacks less effective
    std::string salt = metadata::get("salt");
    value += salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, value.c_str(), value.size());
    SHA256_Final(hash, &sha256);
    std::stringstream hashStream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        hashStream << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];
    }
    return hashStream.str();
}

int auth::authenticate(std::string key_name)
{
    auth::User unauthUser; // unauthenticated user
    RSA *publicKey;
    RSA *privateKey;
    std::string username;

    size_t pos = key_name.find("_");
    username = key_name.substr(0,pos);

    unauthUser.set_user(username);

    publicKey = unauthUser.get_key(AUTH_KEY_TYPE_PUBLIC);
    privateKey = unauthUser.get_key(AUTH_KEY_TYPE_PRIVATE);

    if (publicKey == NULL || privateKey == NULL){
        return 1;
    } 
    
    // Now User authentication
    // We uses private key to decrypt a message that was encrypted with the corresponding public key.
    // If the decryption is successful, the user is authenticated and can proceed with the session.

    char message[] = "My secret";
    char *encryptedContent = NULL;
    char *decryptedContent = NULL;

    // Do RSA encryption using public key
    encryptedContent = (char *)malloc(RSA_size(publicKey));
    int encryptLength = auth::encrypt(strlen(message) + 1, (unsigned char *)message, (unsigned char *)encryptedContent, publicKey);
    if (encryptLength == -1) {
        return 1;
    }
    
    // Try to do RSA decryption using corresponding private key
    decryptedContent = (char *)malloc(encryptLength);
    int decryptLength = auth::decrypt(encryptLength, (unsigned char *)encryptedContent, (unsigned char *)decrypt, privateKey);
    if (decryptLength == -1) {
        return 1;
    }

    if (strcmp(decryptedContent, message) == 0){
        return 0;
    }

    return 1;
}

int auth::user_setup(std::string username)
{
    std::string userRootPath = "filesystem/" + auth::hash(username);
    std::string personalPath = userRootPath + "/" + auth::hash("personal");
    std::string sharedPath = userRootPath + "/" + auth::hash("shared");

    if (
        mkdir(&userRootPath[0], AUTH_DIR_PERMISSION) == 0 &&
        mkdir(&personalPath[0], AUTH_DIR_PERMISSION) == 0 &&
        mkdir(&sharedPath[0], AUTH_DIR_PERMISSION) == 0
    ) {
        std::cout << "User " << username << " folders created successfully" << std::endl;
        metadata::write(auth::hash(username), username);
        return 0;
    } else {
        std::cerr << "Failed to create user folders. Please check permission and try again " << std::endl;
        return 1;
    }
}

RSA *_create_key_pair()
{
    BIGNUM *bne = NULL;
    bne = BN_new();
    BN_set_word(bne, 59);

    RSA *keypair = NULL;
    keypair = RSA_new();
    RSA_generate_key_ex(keypair, 4096, bne, NULL);

    return keypair;
}

int _create_key(int type, std::string path, RSA *key)
{
    int result = -1;
    FILE *fp = fopen(&path[0], "w");
    if (type == AUTH_KEY_TYPE_PRIVATE) {
        result = PEM_write_RSAPrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    } else if (type == AUTH_KEY_TYPE_PUBLIC) {
        result = PEM_write_RSAPublicKey(fp, key);
    }
    std::cout << "result" << result << std::endl;
    return result;
}

// Create public/private key pairs under /publickeys folder and /privatekeys folder
// keyfile's naming convention: username_randomnumber_publickey and username_randomnumber_privatekey
void auth::create_keypair(std::string key_name)
{
    size_t pos = key_name.find("_");
    std::string username = key_name.substr(0, pos);

    std::string publickey_name = username + "_publickey";
    std::string privatekey_name = key_name + "_privatekey";
    std::string publickey_name_sha = auth::hash(publickey_name);
    std::string privatekey_name_sha = auth::hash(privatekey_name);
    std::string publickey_path = "./publickeys/" + publickey_name_sha;
    std::string privatekey_path;

    metadata::write(publickey_name_sha, publickey_name);
    metadata::write(privatekey_name_sha, privatekey_name);

    RSA *keypair = _create_key_pair();

    // generate public key and store to local
    _create_key(AUTH_KEY_TYPE_PUBLIC, publickey_path, keypair);

    if (username == "admin") {
        privatekey_path = privatekey_name_sha;

        // generate private key and store to local
        _create_key(AUTH_KEY_TYPE_PRIVATE, privatekey_path, keypair);
    } else {
        privatekey_path = "filesystem/" + auth::hash(username) + "/" + auth::hash(privatekey_name);
        _create_key(AUTH_KEY_TYPE_PRIVATE, privatekey_path, keypair);

        std::string privatekey_foradmin_path = "./privatekeys/" + auth::hash(username) ;
        _create_key(AUTH_KEY_TYPE_PRIVATE, privatekey_foradmin_path, keypair);
    }
}

int auth::initial_setup()
{
    // Create "filesystem", "privatekeys","publickeys" folders
    if (
        mkdir("filesystem", AUTH_DIR_PERMISSION) == 0 &&
        mkdir("privatekeys", AUTH_DIR_PERMISSION) == 0 &&
        mkdir("publickeys", AUTH_DIR_PERMISSION) == 0
    ) {
        std::cout << "Filesystem created successfully" << std::endl << std::endl;
    } else {
        std::cerr << "Failed to create filesystem. Please check permission and try again " << std::endl;
        return 1;
    }

    // Generate salt and create metadata
    std::string salt = auth::csprng();

    if (metadata::setup(salt)) {
        std::cerr << "Failed to create filesystem. Please check permission and try again " << std::endl;
        return 1;
    }

    return 0;
}
