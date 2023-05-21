
#include <src/auth.h>
#include <src/metadata.h>
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
#include <math.h>

const std::string auth::AUTH_DIR_FILESYSTEM = "filesystem";
const std::string auth::AUTH_DIR_PUBLICKEYS = "publickeys";
const std::string auth::AUTH_DIR_PRIVATEKEYS = "privatekeys";

auth::AuthException::AuthException(std::string msg)
{
     message = msg;
}

std::string auth::AuthException::what()
{
    return message;
}

// Initialize user values
void auth::User::set_user(std::string u, std::string k)
{
    username = u;
    isAdmin = false;
    privateKey = NULL;
    publicKey = NULL;

    if (strcasecmp(username.c_str(), "admin") == 0) {
        isAdmin = true;
    }
    if (k.length() > 0) {
        keyName = k;
    }
    if (username.length() > 0) {
        usernameHashed = auth::hash(username);
    }
}

// Encrypt and save file for user, returns 0 on success and -1 on error
int auth::User::encryptSave(char *contents, std::string path)
{
    RSA *key = get_key(AUTH_KEY_TYPE_PUBLIC);
    if (key == NULL) {
        return -1;
    }

    int remainingSize = strlen(contents);

    int keySize = RSA_size(key); // size of each encrypted chunk

    float chunksCount = ceil((float) strlen(contents) / AUTH_MAX_CHUNK_SIZE);
    int expectedFullSize = (int) chunksCount * keySize;

    char *fullContent = (char *) malloc(expectedFullSize);
    int chunkOffset = 0;

    char *encryptedContent = (char *) malloc(keySize);
    
    for (size_t i = 0; i < chunksCount; i++) {
        int chunkSize = 0;

        if (remainingSize >= AUTH_MAX_CHUNK_SIZE) {
            chunkSize = AUTH_MAX_CHUNK_SIZE;
            remainingSize -= AUTH_MAX_CHUNK_SIZE;
        } else {
            chunkSize = remainingSize;
        }

        char *chunkContent = (char *) malloc(chunkSize + 1);

        memset(chunkContent, 0, chunkSize + 1);
        memset(encryptedContent, 0, keySize);

        memcpy(chunkContent, &contents[chunkOffset], chunkSize);

        int encryptLength = auth::encrypt(strlen(chunkContent) + 1, (unsigned char *) chunkContent, (unsigned char *) encryptedContent, key);
        if (encryptLength == -1) {
            return -1;
        }

        int contentOffset = (keySize * i);
        memcpy(&fullContent[contentOffset], encryptedContent, encryptLength);

        chunkOffset += AUTH_MAX_CHUNK_SIZE;
        free(chunkContent);
    }

    auth::save_file(path, fullContent, expectedFullSize);
    free(fullContent);
    free(encryptedContent);

    return 0;
}

// Decrypt the content based on user's private key, returns decrypted bytes
char *auth::User::decrypt(char *encryptedContents, int fSize)
{
    RSA *key = get_key(AUTH_KEY_TYPE_PRIVATE);
    int keySize = RSA_size(key);

    if (fSize <= 0) {
        fSize = keySize;
    }

    int chunksCount = ceil((float) fSize / keySize);
    char *fullContent = (char *) malloc(fSize);
    memset(fullContent, 0, fSize);

    int chunkOffset = 0;

    for (size_t i = 0; i < chunksCount; i++) {
        char *decryptedContent = (char *) malloc(keySize);
        char *chunkEncrypted = (char *) malloc(keySize);
        memcpy(chunkEncrypted, &encryptedContents[chunkOffset], keySize);

        int decryptLength = auth::decrypt(keySize, (unsigned char *) chunkEncrypted, (unsigned char *) decryptedContent, key);
        if (decryptLength == -1) {
            throw auth::AuthException("An error occurred during decryption");
        }

        strcat(fullContent, decryptedContent);
        free(decryptedContent);
        free(chunkEncrypted);

        chunkOffset += keySize;
    }

    return fullContent;
}

// Get user's RSA (public or private)
RSA *auth::User::get_key(int type)
{
    std::string path;

    if (type == AUTH_KEY_TYPE_PUBLIC) {
        if (publicKey != NULL) {
            return publicKey;
        }
        path = auth::AUTH_DIR_PUBLICKEYS + "/" + auth::hash(username + "_publickey");
        publicKey = auth::get_key(type, path);
        return publicKey;
    } else if (type == AUTH_KEY_TYPE_PRIVATE) {
        if (privateKey != NULL) {
            return privateKey;
        }
        path = auth::AUTH_DIR_PRIVATEKEYS + "/" + usernameHashed;
        privateKey = auth::get_key(type, path);
        return privateKey;
    }

    return NULL;
}

RSA *auth::User::private_key_by_name()
{
    if (privateKey != NULL) {
        return privateKey;
    }
    std::string path;
    if (isAdmin) {
        path = auth::hash(keyName + "_privatekey");
    } else {
        path = auth::AUTH_DIR_FILESYSTEM + "/" + usernameHashed + "/" + auth::hash(keyName + "_privatekey");
    }

    privateKey = auth::get_key(AUTH_KEY_TYPE_PRIVATE, path);
    return privateKey;
}

// Generate random bytes as hex string
std::string auth::csprng()
{
    constexpr size_t rsize = 32;
    unsigned char ran_buf[rsize];
    std::ostringstream result_stream;

    if (RAND_bytes(ran_buf, rsize) != 1) {
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
        throw auth::AuthException("Unable to create file, please check directory permissions");
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
    username = key_name.substr(0, pos);
    unauthUser.set_user(username, key_name);
    
    publicKey = unauthUser.get_key(AUTH_KEY_TYPE_PUBLIC);
    privateKey = unauthUser.private_key_by_name();

    if (publicKey == NULL || privateKey == NULL) {
        return 1;
    } 
    
    // Now User authentication
    // We uses private key to decrypt a message that was encrypted with the corresponding public key.
    // If the decryption is successful, the user is authenticated and can proceed with the session.

    char message[] = "My secret"; // this is OK to be hard-coded
    char *encryptedContent = NULL;
    char *decryptedContent = NULL;

    // Do RSA encryption using public key
    encryptedContent = (char *) malloc(RSA_size(publicKey));
    int encryptLength = auth::encrypt(strlen(message) + 1, (unsigned char *) message, (unsigned char *) encryptedContent, publicKey);
    if (encryptLength == -1) {
        return 1;
    }
    
    // Try to do RSA decryption using corresponding private key
    decryptedContent = (char *) malloc(encryptLength);
    int decryptLength = auth::decrypt(encryptLength, (unsigned char *) encryptedContent, (unsigned char *) decryptedContent, privateKey);
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
    std::string userRootPath = auth::AUTH_DIR_FILESYSTEM + "/" + auth::hash(username);
    std::string personalPath = userRootPath + "/" + auth::hash("personal");
    std::string sharedPath = userRootPath + "/" + auth::hash("shared");

    if (
        mkdir(&userRootPath[0], AUTH_DIR_PERMISSION) != 0 ||
        mkdir(&personalPath[0], AUTH_DIR_PERMISSION) != 0 ||
        mkdir(&sharedPath[0], AUTH_DIR_PERMISSION) != 0
    ) {
        std::cerr << "Failed to create user folders. Please check permission and try again " << std::endl;
        return 1;
    }
    metadata::write(auth::hash(username), username);
    return 0;
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
    std::string publickey_path = auth::AUTH_DIR_PUBLICKEYS + "/" + publickey_name_sha;
    std::string privatekey_path;

    metadata::write(publickey_name_sha, publickey_name);
    metadata::write(privatekey_name_sha, privatekey_name);

    RSA *keypair = _create_key_pair();

    // generate public key and store to local
    _create_key(AUTH_KEY_TYPE_PUBLIC, publickey_path, keypair);

    if (is_admin(username)) {
        privatekey_path = privatekey_name_sha;

        // generate private key and store to local
        _create_key(AUTH_KEY_TYPE_PRIVATE, privatekey_path, keypair);
    } else {
        privatekey_path = auth::AUTH_DIR_FILESYSTEM + "/" + auth::hash(username) + "/" + auth::hash(privatekey_name);
        _create_key(AUTH_KEY_TYPE_PRIVATE, privatekey_path, keypair);

        std::string privatekey_foradmin_path = auth::AUTH_DIR_PRIVATEKEYS + "/" + auth::hash(username) ;
        _create_key(AUTH_KEY_TYPE_PRIVATE, privatekey_foradmin_path, keypair);
    }
}

int auth::initial_setup()
{
    // Create "filesystem", "privatekeys","publickeys" folders
    if (
        mkdir(auth::AUTH_DIR_FILESYSTEM.c_str(), AUTH_DIR_PERMISSION) != 0 ||
        mkdir(auth::AUTH_DIR_PRIVATEKEYS.c_str(), AUTH_DIR_PERMISSION) != 0 ||
        mkdir(auth::AUTH_DIR_PUBLICKEYS.c_str(), AUTH_DIR_PERMISSION) != 0
    ) {
        throw auth::AuthException("Failed to create filesystem. Please check permission and try again.");
    }

    // Generate salt and create metadata
    std::string salt = auth::csprng();

    if (metadata::setup(salt)) {
        throw auth::AuthException("Failed to create filesystem. Please check permission and try again.");
    }

    return 0;
}

// Returns 1 on initial setup and 0 on authenticated
int auth::validate(std::string &key_name, auth::User &currentUser)
{
    struct stat filesystemStat, publicKeyStat, privateKeyStat;
    int filesystemResult, publicKeyResult, privateKeyResult;

    filesystemResult = stat(auth::AUTH_DIR_FILESYSTEM.c_str(), &filesystemStat);
    publicKeyResult = stat(auth::AUTH_DIR_PUBLICKEYS.c_str(), &publicKeyStat);
    privateKeyResult = stat(auth::AUTH_DIR_PRIVATEKEYS.c_str(), &privateKeyStat);

    if (
        filesystemResult == -1 &&
        publicKeyResult == -1 &&
        privateKeyResult == -1
    ) {
        //Initial Setup
        if (auth::initial_setup() == 1) {
            throw auth::AuthException("Unable to perform initial setup. Please try again.");
        }

        metadata::write(auth::hash("personal"), "personal");
        metadata::write(auth::hash("shared"), "shared");

        std::string username = "admin";
        std::string randomKey = auth::csprng();
        if (randomKey.length() == 0) {
            throw auth::AuthException("Unable to generate random key. Please try again.");
        }
        key_name = username + "_" + randomKey;

        auth::create_keypair(key_name);
        return 1;
    } else if (
        filesystemResult == -1 ||
        publicKeyResult == -1 ||
        privateKeyResult == -1) {
        throw auth::AuthException("Partial file system exist. Please remove folder filesystem/privatekeys/publickeys and try again.");
    } else {
        int login_result = auth::authenticate(key_name);
        if (login_result == 1) {
            throw auth::AuthException("Invalid key_name is provided. Fileserver closed.");
        } else {
            size_t pos = key_name.find("_");
            std::string username = key_name.substr(0,pos);
            currentUser.set_user(username, key_name);
        }
    }
    return 0;
}