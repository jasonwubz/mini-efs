#include <command.h>
#include <metadata.h>
#include <auth.h>
#include <cstdlib>
#include <unistd.h>
#include <string.h>
#include <ostream>
#include <vector>
#include <iostream>
#include <filesystem>
#include <algorithm>
#include <iomanip>
#include <regex>
#include <sys/types.h>
#include <sys/stat.h>

#define DIR_PERMISSION 0744

void command::adduser(std::string username)
{
    // create user folders
    int result = auth::user_folder_setup(username);
    if (result) {
        return;
    }

    std::string randomKey = auth::csprng();
    if (randomKey.length() == 0) {
        return;
    }
    std::string key_name = username + "_" + randomKey;
    
    auth::create_RSA(key_name);
    std::cout << "User " << username << " Public/Private key pair has been created." << std::endl;
    std::cout << "The private key_name is " << key_name << std::endl;
    std::cout << "Please give this key_name to user and let user know that it must be remained secret to him/herself only." << std::endl;
    std::cout << "User " << username << " can login by command: " << std::endl;
    std::cout << "./fileserver " << key_name << std::endl << std::endl;
}

void command::ls(std::vector<std::string>&dir, std::string username)
{
    // construct current directory string
    std::string cur_dir;
    bool upper_dir = false;
    std::cout << "d -> ."<< std::endl;
    
    if (auth::is_admin(username)) {
        cur_dir = std::filesystem::current_path().string() + "/filesystem/";
    } else{
        cur_dir = std::filesystem::current_path().string() + "/filesystem/" + auth::hash(username);
    }
    for (std::string str : dir) {
        if (!str.empty()) {
            cur_dir = cur_dir + '/' + auth::hash(str);
            upper_dir = true;
        }
    }
    if (upper_dir) {
        std::cout << "d -> .." << std::endl;
    }
    
    // iterate directory
    const std::filesystem::path path = std::filesystem::u8path(cur_dir); // sanity check for encoding
    for (const auto & entry : std::filesystem::directory_iterator(path)) {
        std::string prefix;
        std::string full_path = entry.path();
        std::string sub_path = full_path.substr(cur_dir.length());
        if (std::filesystem::is_directory(std::filesystem::status(full_path))) {
            prefix = "d -> ";
        } else {
            prefix = "f -> ";
        }
        std::string display_path;
        if (sub_path[0] == '/') {
            display_path = auth::hash_to_val(full_path.substr(cur_dir.length() + 1));
        } else {
            display_path = auth::hash_to_val(full_path.substr(cur_dir.length()));
        }
        if (display_path != "") {
            std::cout << prefix + display_path << std::endl;
        }
    }
}

void command::help(bool isAdmin)
{
    std::cout << std::endl;
    std::cout << "Available commands:" << std::endl;
    std::cout << "-------------------" << std::endl;

    std::cout << "cd <directory>               - Change directory" << std::endl;
    std::cout << "pwd                          - Print the current directory" << std::endl;
    std::cout << "ls                           - List the files and directories in the current directory" << std::endl;
    std::cout << "cat <filename>               - Print content of the given filename" << std::endl;
    

    if (isAdmin) {
        std::cout << "adduser <username>           - Add new user by given username" << std::endl;
    } else {
        std::cout << "share <filename> <username>  - Share the file <filename> with the target user <username>" << std::endl;
        std::cout << "mkfile <filename> <contents> - Create a new file <filename> with the ascii printable contents <contents>" << std::endl;
    }

    std::cout << "exit                         - Terminate the program" << std::endl;
}

std::string command::pwd(std::vector<std::string>& dir)
{
    std::string result;
    if (dir.empty()) {
        result += "/";
    } else {
        for (std::string str:dir) {
            result += "/" + str;
        }
    }
    return result;
}

void command::cd(std::vector<std::string>& dir, std::string change_dir, std::string username)
{
    std::stringstream test(change_dir);
    std::string segment;
    std::vector<std::string> seglist;
    std::vector<std::string> new_dir;

    // split input by '/'
    while(getline(test, segment, '/')) {
        seglist.push_back(segment);
    }
    
    // if the input started by "." or "..", use the current directory for prefix
    if (seglist[0] == "." || seglist[0] == ".." || !seglist[0].empty()) {
        new_dir = dir;
    }
    
    // build new directory
    for (std::string seg : seglist) {
        if (seg == "." || seg.empty()) {
            continue;
        } else if (seg == "..") {
            if (new_dir.empty()) {
                std::cout << "Invalid directory!" << std::endl;
                return;
            }
            new_dir.pop_back();
        } else {
            new_dir.push_back(seg);
        }
    }

    // convert new directory to string in order to use std::filesystem functions
    std::string check_dir = std::filesystem::current_path().string() + "/" + "filesystem";
    if (!auth::is_admin(username)) {
        check_dir = check_dir + "/" + auth::hash(username);
    }
    for (std::string str : new_dir) {
        if (!str.empty()) {
            check_dir = check_dir + "/" + auth::hash(str);
        }
    }
    if (std::filesystem::is_directory(std::filesystem::status(check_dir)) ) {
        dir = new_dir;
        std::cout << "Change directory to: ";
        std::cout << command::pwd(dir) << std::endl; 
    } else {
        std::cout << "Invalid directory!" << std::endl;
    }

    return;
}

void command::makedir(std::vector<std::string>& dir, std::string new_dir, std::string username)
{
    std::string cur_dir;
    for (std::string str:dir) {
        cur_dir = cur_dir + '/' + auth::hash(str);
    }

    if (new_dir.find(".") != -1 or new_dir.find("..") != -1 or new_dir.find("/") != -1) {
        std::cout << "Invalid directory name." << std::endl;
        return;
    }

    if (username != "Admin") {
        if (!dir.empty()) {
            if (cur_dir.substr(1,65) == auth::hash("shared")) {
                std::cout << "Forbidden: Cannot create directory in /shared" << std::endl;
            } else {
                metadata::write(auth::hash(new_dir),new_dir);
                new_dir = std::filesystem::current_path().string() + "/filesystem/" + auth::hash(username) + '/' + cur_dir.substr(1) + '/' + auth::hash(new_dir);

                char* dirname = strdup(new_dir.c_str());
                if (mkdir(dirname, DIR_PERMISSION) == -1) {
                    std::cerr << "Error: directory exists."<< std::endl;
                } else {
                    std::cout << "Directory created" << std::endl;
                }
                free(dirname);
            }
        } else {
            std::cout << "Forbidden" << std::endl;
        }
    } else {
        std::cout << "Invalid command for admin!" << std::endl;
    }
}

void command::mkfile(const std::string& username, const std::string& filename, const std::string& curr_dir, const std::string& contents)
{
    std::string hashed_filename = auth::hash(filename);
    metadata::write(hashed_filename, filename);
    std::string full_path = "filesystem/" + auth::hash(username) + "/" + curr_dir + hashed_filename;

    char* message = new char[contents.length() + 1];
    strcpy(message, contents.c_str());

    char* encrypt;

    std::string public_key_path = "./publickeys/" + auth::hash(username + "_publickey");
    RSA* public_key = auth::read_RSAkey("public", public_key_path);

    if (public_key == NULL) {
        std::cout << "Error! Public key not found or invalid" << std::endl;
        return;
    }

    encrypt = (char*)malloc(RSA_size(public_key));
    int encrypt_length = auth::public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_OAEP_PADDING);
    if (encrypt_length == -1) {
        std::cout << "An error occurred in public_encrypt() method" << std::endl;
        return;
    }

    auth::create_encrypted_file(full_path, encrypt, public_key);

    // check for expected shared file and update it
    std::string expected_path_suffix = "/" + auth::hash("shared") + "/" + auth::hash(username) + "/" + hashed_filename;
    for (const auto & entry : std::filesystem::directory_iterator("./filesystem")) {
        std::string full_path = entry.path();
        std::string shared_user = auth::hash_to_val(full_path.substr(13));
        full_path += expected_path_suffix;
        // cout << full_path << endl;
        if (std::filesystem::exists(full_path)) {
            RSA *target_public_key;
            target_public_key = auth::read_RSAkey("public", "./publickeys/" + auth::hash(shared_user + "_publickey"));
            if (target_public_key == NULL) {
                // for some reason, the target's public key is lost so we cannot update it
                continue;
            }

            char* share_encrypted_content = (char*)malloc(RSA_size(target_public_key));
            int share_encrypt_length = auth::public_encrypt(contents.length() + 1, (unsigned char*)contents.c_str(), (unsigned char*)share_encrypted_content, target_public_key, RSA_PKCS1_OAEP_PADDING);
            if (share_encrypt_length == -1) {
                // failed to encrypt
                continue;
            }
            auth::create_encrypted_file(full_path, share_encrypted_content, target_public_key);
            free(share_encrypted_content);
        }
    }
    free(encrypt);
    delete[] message;
}