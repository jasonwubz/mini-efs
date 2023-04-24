
#include <auth.h>
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

using namespace auth;

std::string auth::csprng() {
    constexpr size_t rsize = 32;
    unsigned char ran_buf[rsize];
    std::ostringstream result_stream;

    if (RAND_bytes(ran_buf, rsize) != 1) {
        std::cout << "Error generating private key name";
        return "";
    }

    for (size_t i = 0; i < rsize; i++) {
        result_stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ran_buf[i]);
    }

    return result_stream.str();
}

// This function implement RSA public key encryption
int auth::public_encrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {
    
    int result = RSA_public_encrypt(flen, from, to, key, padding);
    return result;
}

// This function implement RSA private key decryption
int auth::private_decrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {
    int result = RSA_private_decrypt(flen, from, to, key, padding);
    return result;
}

// In mkfile and mkdir, we need to calculate the key: value pair and store it in metadata.json
void auth::write_to_metadata(std::string sha, std::string name) {
    std::ifstream ifs("metadata.json");
    Json::Value metadata;
    Json::CharReaderBuilder builder;
    JSONCPP_STRING err;
    Json::parseFromStream(builder, ifs, &metadata, &err);
    
    // Add a new key-value pair to the Json::Value object
    metadata[sha] = name;

    // Write the modified Json::Value object back to the JSON file
    std::ofstream ofs("metadata.json");
    Json::StreamWriterBuilder writerBuilder;
    std::unique_ptr<Json::StreamWriter> writer(writerBuilder.newStreamWriter());
    writer->write(metadata, &ofs);
}

// This function will read RSA (public or private) keys specified by key_path
RSA * auth::read_RSAkey(std::string key_type, std::string key_path){
    
    FILE  *fp  = NULL;
    RSA   *rsa = NULL;

    fp = fopen(&key_path[0], "rb");
    if (fp == NULL){
        //invalid key_name provided
        return rsa;
    }

    if (key_type == "public"){
        PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
        fclose(fp);        
    } else if (key_type == "private"){
        PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
        fclose(fp);
    }
    return rsa;
}

// Read metadata.json, use sha value as key to get back the file or directory name
std::string auth::hash_to_val(std::string sha) {
    std::ifstream ifs("metadata.json");
    Json::Value metadata;
    Json::CharReaderBuilder builder;
    JSONCPP_STRING err;
    Json::parseFromStream(builder, ifs, &metadata, &err);

    std::string name = metadata[sha].asString();
    return name;
}

// Give it a file or directory name, return the SHA-256 hash value
std::string auth::hash(std::string name) {
    // Append salt before calculating the sha256 hash. So attacker can no longer find the original by checking common hash value websites
    std::string salt = auth::hash_to_val("salt");
    name += salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, name.c_str(), name.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];
    }
    return ss.str();
}

int auth::login_authentication(std::string key_name){
    RSA *private_key;
    RSA *public_key;
    std::string public_key_path, private_key_path, username;

    size_t pos = key_name.find("_");
    username = key_name.substr(0,pos);

    std::string publickey_name = username + "_publickey";
    std::string privatekey_name = key_name + "_privatekey";
    
    public_key_path = "./publickeys/" + auth::hash(publickey_name);
    public_key = auth::read_RSAkey("public", public_key_path);    

    if (username == "Admin"){
        private_key_path = auth::hash(privatekey_name);
    } else {
        private_key_path = "./filesystem/" + auth::hash(username) + "/" + auth::hash(privatekey_name);
    }
    private_key = read_RSAkey("private", private_key_path);
    
    if (public_key == NULL || private_key == NULL){
        //not such key by searching the provided key_name
        // cout << "Invalid key_name is provided. Fileserver closed." << endl;
        return 1;
    } else {
        // Successfully read public key and private key. Now User authentication
        // We uses private key to decrypt a message that was encrypted with the corresponding public key.
        // If the decryption is successful, the user is authenticated and can proceed with the session.

        char message[] = "My secret";
        char *encrypt = NULL;
        char *decrypt = NULL;

        // Do RSA encryption using public key
        encrypt = (char*)malloc(RSA_size(public_key));
        int encrypt_length = public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_OAEP_PADDING);
        if(encrypt_length == -1) {
            // cout << "An error occurred in public_encrypt() method" << endl;
            return 1;
        }
        
        // Try to do RSA decryption using corresponding private key
        decrypt = (char *)malloc(encrypt_length);
        int decrypt_length = private_decrypt(encrypt_length, (unsigned char*)encrypt, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);
        if(decrypt_length == -1) {
            // cout << "An error occurred in private_decrypt() method" << endl;
            return 1;
        }
        if (strcmp(decrypt, message) == 0){
            // cout << "Successfully login" << endl;
            // cout << decrypt << endl;
            return 0;
        } else {
            return 1;
        }
    }
}

int auth::user_folder_setup(std::string new_username){
    std::string root_folder_path = "filesystem/" + auth::hash(new_username);
    std::string personal_folder_path = root_folder_path + "/" + auth::hash("personal");
    std::string shared_folder_path = root_folder_path + "/" + auth::hash("shared");

    int status1 = mkdir(&root_folder_path[0], 0744);
    int status2 = mkdir(&personal_folder_path[0], 0744);
    int status3 = mkdir(&shared_folder_path[0], 0744);

    if (status1 == 0 && status2 == 0 && status3 == 0) {
        std::cout << "User " << new_username << " folders created successfully" << std::endl << std::endl;
        write_to_metadata(auth::hash(new_username),new_username);
        return 0;
    } else {
        std::cerr << "Failed to create user folders. Please check permission and try again " << std::endl;
        return 1;
    }
}

// This function will create public/private key pairs under /publickeys folder and /privatekeys folder
// keyfile's naming convension: username_randomnumber_publickey and username_randomnumber_privatekey
void auth::create_RSA(std::string key_name) {
    size_t pos = key_name.find("_");
    std::string username = key_name.substr(0,pos);

    if (username == "Admin") {

        std::string publickey_name = username + "_publickey";
        std::string privatekey_name = key_name + "_privatekey";
        std::string publickey_name_sha = auth::hash(publickey_name);
        std::string privatekey_name_sha = auth::hash(privatekey_name);

        std::string publickey_path = "./publickeys/" + publickey_name_sha;
        std::string privatekey_path = privatekey_name_sha;

        write_to_metadata(publickey_name_sha, publickey_name);
        write_to_metadata(privatekey_name_sha, privatekey_name);
        
        RSA   *rsa = NULL;
        FILE  *fp  = NULL;
        FILE  *fp1  = NULL;

        BIGNUM *bne = NULL;
        bne = BN_new();
        BN_set_word(bne, 59);

        RSA *keypair = NULL;
        keypair = RSA_new();
        //2048 bit key
        RSA_generate_key_ex(keypair, 4096, bne, NULL);

        //generate public key and store to local
        fp = fopen(&publickey_path[0], "w");
        PEM_write_RSAPublicKey(fp, keypair);
        fclose(fp);
        
        //generate private key and store to local
        fp1 = fopen(&privatekey_path[0], "w");
        PEM_write_RSAPrivateKey(fp1, keypair, NULL, NULL, 0, NULL, NULL);
        fclose(fp1);
    } else {
        // normal user's public key & private key file creation
        std::string publickey_name = username + "_publickey";
        std::string privatekey_name = key_name + "_privatekey";

        std::string publickey_name_sha = auth::hash(publickey_name);
        std::string privatekey_name_sha = auth::hash(privatekey_name);

        write_to_metadata(publickey_name_sha, publickey_name);
        write_to_metadata(privatekey_name_sha, privatekey_name);

        std::string publickey_path = "./publickeys/" + auth::hash(publickey_name);
        std::string privatekey_path = "filesystem/" + auth::hash(username) + "/" + auth::hash(privatekey_name);
        std::string privatekey_foradmin_path = "./privatekeys/" + auth::hash(username) ;
        
        RSA   *rsa = NULL;
        FILE  *fp  = NULL;
        FILE  *fp1  = NULL;
        FILE  *fp2  = NULL;

        BIGNUM *bne = NULL;
        bne = BN_new();
        BN_set_word(bne, 59);

        RSA *keypair = NULL;
        keypair = RSA_new();
        RSA_generate_key_ex(keypair, 4096, bne, NULL);

        //generate public key and store to local
        fp = fopen(&publickey_path[0], "w");
        PEM_write_RSAPublicKey(fp, keypair);
        fclose(fp);
        
        //generate private key and store to local
        fp1 = fopen(&privatekey_path[0], "w");
        PEM_write_RSAPrivateKey(fp1, keypair, NULL, NULL, 0, NULL, NULL);
        fclose(fp1);

        //Store a copy of private key in privatekeys for admin usage only
        fp2 = fopen(&privatekey_foradmin_path[0], "w");
        PEM_write_RSAPrivateKey(fp2, keypair, NULL, NULL, 0, NULL, NULL);
        fclose(fp2);
    }
}

