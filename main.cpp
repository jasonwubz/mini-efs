#include <auth.h>
#include <command.h>
#include <metadata.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <cstdlib>
#include <string.h>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <regex>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <sys/stat.h>
#include <sys/types.h>
#include <jsoncpp/json/json.h>

int initial_folder_setup(){
    //create "filesystem", "privatekeys","publickeys" folders
    int status1 = mkdir("filesystem", 0744);
    int status2 = mkdir("privatekeys", 0744);
    int status3 = mkdir("publickeys", 0744);

    if (status1 == 0 && status2 == 0 && status3 == 0){
        std::cout << "Filesystem created successfully" << std::endl << std::endl;
    } else {
        std::cerr << "Failed to create filesystem. Please check permission and try again " << std::endl;
        return 1;
    }

    // Create an empty json file metadata.json
    Json::Value metadata;
    std::ofstream ofs("./metadata.json");
    Json::StreamWriterBuilder writerBuilder;
    std::unique_ptr<Json::StreamWriter> writer(writerBuilder.newStreamWriter());
    writer->write(metadata, &ofs);

    return 0;
}

void initial_adminkey_setup()
{
    std::string username = "Admin";
    std::string random_byte_hex = auth::csprng();
    if (random_byte_hex.length() == 0) {
        return;
    }
    std::string key_name = username + "_" + random_byte_hex;

    auth::create_RSA(key_name);
    std::cout << "Admin Public/Private key pair has been created." << std::endl;
    std::cout << "Your private key_name is " << key_name << std::endl;
    std::cout << "Please store your key_name safely. Admin can login by command: " << std::endl;
    std::cout << "./fileserver " << key_name << std::endl << std::endl;
}

std::vector<std::string> split_string(const std::string& ipstr, const std::string& delimiter)
{
    size_t pos;
    std::string token;
    std::string ipstrcpy = ipstr;
    std::vector<std::string> splits;
    while ((pos = ipstrcpy.find(delimiter)) != std::string::npos) {
        token = ipstrcpy.substr(0, pos);
        splits.push_back(token);
        ipstrcpy.erase(0, pos + delimiter.length());
    }
    splits.push_back(ipstrcpy);
    return splits;
}

bool check_invalid_username(std::string username) {
    for(int i=0;i<username.length();i++){
        if(!std::isalpha(username[i]) && !std::isdigit(username[i])) {return false;}
    }
    return true;
}

std::string command_cat(const std::string& username, const std::string& filename, const std::string& curr_dir, const std::string& key_name)
{
    std::string hashed_filename = auth::hash(filename);
    std::string full_path = "filesystem/" + auth::hash(username) + "/" + curr_dir + hashed_filename;

    struct stat s;
    if (stat(full_path.c_str(), &s) == 0) {
        if (s.st_mode & S_IFDIR) {
            std::cout << "Cannot open a directory, please enter a file name" << std::endl;
            return "";
        }
    }

    std::ifstream infile(full_path);

    if (!(infile && infile.is_open())) {
        std::cout << "Unable to open the file, please check file name" << std::endl;
        return "";
    }

    infile.seekg(0, std::ios::end);
    size_t length = infile.tellg();
    infile.seekg(0, std::ios::beg);

    std::string public_key_path = "./publickeys/" + auth::hash(username + "_publickey");
    RSA *public_key = auth::read_RSAkey("public", public_key_path);

    if (public_key == NULL) {
        std::cout << "Error! Public key not found or invalid" << std::endl;
        return "";
    }

    char *contentss = (char*)malloc(RSA_size(public_key));;
    infile.read(contentss, length);
    infile.close();

    char *decrypt;

    std::string private_key_path;
    RSA *private_key;
    private_key_path = "./filesystem/" + auth::hash(username) + "/" + auth::hash(key_name + "_privatekey");
    private_key = auth::read_RSAkey("private", private_key_path);

    decrypt = (char*)malloc(RSA_size(public_key));

    if (private_key == NULL) {
        std::cout << "Error! Private key not found or invalid" << std::endl;
        return "";
    }

    int decrypt_length = auth::private_decrypt(RSA_size(private_key), (unsigned char*)contentss, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);
    if (decrypt_length == -1) {
        std::cout << "An error occurred in private_decrypt() method" << std::endl;
    }

    std::string output = decrypt;
    free(decrypt);
    return output;
}

std::string command_cat_admin(const std::string& username, const std::string& filename, const std::string& curr_dir, const std::string& key_name)
{
    std::string hashed_filename = auth::hash(filename);
    std::string full_path = "filesystem/" + curr_dir + hashed_filename;

    struct stat s;
    if (stat(full_path.c_str(), &s) == 0 ) {
        if (s.st_mode & S_IFDIR){
            std::cout << "Cannot open a directory, please enter a file name" << std::endl;
            return "";
        }
    }

    std::ifstream infile(full_path);

    if (!(infile && infile.is_open())) {
        std::cout << "Unable to open the file, please check file name" << std::endl;
        return "";
    }

    infile.seekg(0, std::ios::end);
    size_t length = infile.tellg();
    infile.seekg(0, std::ios::beg);

    std::string public_key_path = "./publickeys/" + auth::hash(username + "_publickey");
    RSA *public_key = auth::read_RSAkey("public", public_key_path);

    if (public_key == NULL) {
        std::cout << "Error! Public key not found or invalid" << std::endl;
        return "";
    }

    char *contents = (char*)malloc(RSA_size(public_key));;
    infile.read(contents, length);
    infile.close();

    char *decrypt;

    std::string private_key_path;
    RSA *private_key;
    private_key_path = "./privatekeys/" + auth::hash(username);

    private_key = auth::read_RSAkey("private", private_key_path);

    decrypt = (char*)malloc(RSA_size(public_key));

    if (private_key == NULL) {
        std::cout << "Error! Private key not found or invalid" << std::endl;
        return "";
    }

    int decrypt_length = auth::private_decrypt(RSA_size(private_key), (unsigned char*)contents, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);
    if (decrypt_length == -1) {
        std::cout << "An error occurred in private_decrypt() method" << std::endl;
    }

    return decrypt;
}

bool is_admin(std::string username)
{
    if (strcasecmp(username.c_str(), "admin") == 0) {
        return true;
    }
    return false;
}

void command_sharefile(std::string username, std::string key_name, std::vector<std::string>& dir, std::string user_command)
{
    // check who is the username
    if (is_admin(username) == true) {
        std::cout << "Forbidden" << std::endl;
        return;
    }

    // group 1 must always be 'share', group 4 if using quotes or group 6 without quotes, group 7 is the user
    // regex rgx("^([A-Za-z0-9]+)\\s+((\"|')?([A-Za-z0-9\\s.]+)(\\3)|([A-Za-z0-9.]+))\\s+([a-z0-9]+)");
    std::regex rgx("^share\\s+((\"|')?([A-Za-z0-9\\-_\\s.]+)(\\3)|([A-Za-z0-9\\-_.]+))\\s+([a-z0-9_]+)");
    
    std::smatch matches;

    std::string filename, target_username, match_string;
    if (regex_search(user_command, matches, rgx)) {
        for (size_t i = 0; i < matches.size(); ++i) {
            match_string = matches[i].str();
            if ((i == 3 || i == 5) && match_string.length() > 0) {
                filename = match_string;
            }
            if (i == 6) {
                target_username = match_string;
            }
        }
    } else {
        std::cout << "Invalid share command. You should use command: " << std::endl;
        std::cout << "share <filename> <username>" << std::endl;
        return;
    }

    // check file exists by reading it
    std::string hashed_pwd;
    for (int i = 0; i < dir.size(); i++) {
        std::string hashed_dir = auth::hash(dir[i]);
        hashed_pwd += "/" + hashed_dir;
    }

    std::string hashed_username = auth::hash(username);
    std::string hashed_filename = auth::hash(filename);
    std::string filepath = "./filesystem/" + hashed_username + hashed_pwd + "/" + hashed_filename;

    struct stat s;
    if(stat(filepath.c_str(), &s) == 0) {
        if(s.st_mode & S_IFDIR) {
            std::cout << "Cannot share a directory, please enter a file name" << std::endl;
            return;
        }
    }

    std::ifstream ifs;
    ifs.open(filepath);
    if (!(ifs && ifs.is_open())) {
        std::cout << "Filename '" << filename << "' does not exist." << std::endl;
        return;
    }
    ifs.seekg(0, std::ios::end);
    size_t full_size = ifs.tellg();
    // rewind to allow reading
    ifs.seekg(0, std::ios::beg);

    // create file content buffer
    char* file_content = new char[full_size];
    ifs.read(file_content, full_size);
    ifs.close();

    // check that the user cannot share to themselves
    if (target_username == username) {
        std::cout << "You cannot share files to yourself." << std::endl;
        return;
    }
    
    RSA *private_key;
    std::string private_key_path = "./filesystem/" + hashed_username + "/" + auth::hash(key_name + "_privatekey");
    private_key = auth::read_RSAkey("private", private_key_path);
    if (private_key == NULL) {
        std::cout << "Error! Private key not found or invalid" << std::endl;
        return;
    }
    if (private_key_path == filepath) {
        std::cout << "You cannot share your private key." << std::endl;
        return;
    }

    // check that target username exists (a valid user have a public key)
    RSA *target_public_key;
    std::string hashed_target_username = auth::hash(target_username);
    target_public_key = auth::read_RSAkey("public", "./publickeys/" + auth::hash(target_username + "_publickey"));
    if (target_public_key == NULL) {
        std::cout << "Error! Public key not found or invalid" << std::endl;
        return;
    }
    if (target_public_key == NULL){
        std::cout << "User '" << target_username << "' does not exists." << std::endl;
        return;
    }

    // decrypt file for copying
    char *decrypted_file_content = new char[full_size];
    int decrypt_length = auth::private_decrypt(full_size, (unsigned char*)file_content, (unsigned char*)decrypted_file_content, private_key, RSA_PKCS1_OAEP_PADDING);
    if (decrypt_length == -1) {
        std::cout << "An error occurred during file share" << std::endl;
        return;
    }

    // encrypt shared file with target's public key
    char *share_encrypted_content = (char*)malloc(RSA_size(target_public_key));
    int share_encrypt_length = auth::public_encrypt(strlen(decrypted_file_content) + 1, (unsigned char*)decrypted_file_content, (unsigned char*)share_encrypted_content, target_public_key, RSA_PKCS1_OAEP_PADDING);
    if (share_encrypt_length == -1) {
        std::cout << "An error occurred during file share" << std::endl;
        return;
    }

    // directory exists?
    std::string target_share_directory = "./filesystem/" + hashed_target_username + "/" + auth::hash("shared") +"/" + hashed_username;
    // cout << "Target directory:" << target_share_directory << endl;
    if (!std::filesystem::is_directory(std::filesystem::status(target_share_directory))) {
        int dir_create_status = mkdir(&target_share_directory[0], 0744);
        if (dir_create_status != 0) {
            std::cout << "An error occurred during file share" << std::endl;
            return;
        }
    }

    // now write new file
    std::string target_filepath = target_share_directory + "/" + hashed_filename;
    auth::create_encrypted_file(target_filepath, share_encrypted_content, target_public_key);
    std::cout << "File '" << filename << "' has been successfully shared with user '" << target_username << "'" << std::endl;
}

bool isWhitespace(std::string s)
{
    for (int index = 0; index < s.length(); index++) {
        if(!std::isspace(s[index]))
            return false;
    }
    return true;
}

int main(int argc, char** argv)
{
    std::string username, user_command, key_name;

    if (argc != 2) {
        std::cout << "Wrong command to start the fileserver. You should use command: " << std::endl;
        std::cout << "./fileserver key_name" << std::endl;
        return 1;
    }

    std::cout << "--------------------------------------------------------" << std::endl;
    std::cout << "     You are accessing Encrypted Secure File System     " << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl << std::endl;

    struct stat st, st1, st2;
    if (stat("filesystem", &st) == -1 && stat("privatekeys", &st1) == -1 && stat("publickeys", &st2) == -1) {
        //Initial Setup
        std::cout << "No file system exists yet. Execute Initial setup..." << std::endl << std::endl;

        int folder_result = initial_folder_setup();
        if (folder_result == 1) {
            return 1;
        }

        //Generate random salt value using cryptographically secure random function
        std::string random_salt = auth::csprng();
        metadata::write("salt", random_salt);

        metadata::write(auth::hash("personal"), "personal");
        metadata::write(auth::hash("shared"), "shared");

        initial_adminkey_setup();

        std::cout << "Initial setup finshed, Fileserver closed. Admin now can login using the admin keyfile" << std::endl;
        return 0;

    } else if (stat("filesystem", &st) == -1 || stat("privatekeys", &st1) == -1 || stat("publickeys", &st2) == -1) {
        std::cout << "Partial file system exist. Please remove folder filesystem/privatekeys/publickeys and try again." << std::endl;
        return 1;
    } else {
        // Time to do user authentication

        key_name = argv[1];
        int login_result = auth::login_authentication(key_name);
        if (login_result == 1) {
            std::cout << "Invalid key_name is provided. Fileserver closed." << std::endl;
            return 1;
        } else {
            size_t pos = key_name.find("_");
            username = key_name.substr(0,pos);
            std::cout << "Welcome! Logged in as " << username << std::endl;
            command::help(is_admin(username));
        }
    }

    /* ....Implement fileserver different commands...... */
    std::vector<std::string> dir;
    
    while (true) {
        std::cout << std::endl;
        std::cout << "> ";
        getline(std::cin, user_command);
        // cout << "User input: " << user_command << endl;
        std::vector<std::string> splits = split_string(user_command, " ");

        if (user_command == "exit") {
            std::cout << "Fileserver closed. Goodbye " << username << " :)" << std::endl;
            return 0;
        } else if (user_command == "pwd") {
            std::cout << command::pwd(dir) << std::endl;
        } else if (user_command.substr(0, 2) == "cd" && user_command.substr(2, 1) == " ") {
            command::cd(dir, user_command.substr(3), username);
        } else if (user_command == "ls") {
            command::ls(dir, username);
        } else if (user_command.substr(0,5) == "mkdir" && user_command.substr(5,1) == " " && !isWhitespace(user_command.substr(6)) ) {
            command::makedir(dir, user_command.substr(6), username);
        } else if (user_command.rfind("share", 0) == 0) {
            command_sharefile(username, key_name, dir, user_command);
        } else if (splits[0] == "cat") {
            if (splits.size() < 2) {
                std::cout << "Please provide filename" << std::endl;
                continue;
            }

            std::string curr_dir;
            std::string curr_dir_hashed;
            for (const std::string& str:dir) {
                curr_dir.append(str);
                curr_dir_hashed.append(auth::hash(str));
                curr_dir.append("/");
                curr_dir_hashed.append("/");
            }

            if (curr_dir.empty()) {
                std::cout << "Forbidden" << std::endl;
                continue;
            }

            if (splits[1].find("_publickey", 0) != std::string::npos || splits[1].find("_privatekey", 0) != std::string::npos || (splits[1].find("..", 0) != std::string::npos)) {
                std::cout << "Forbidden" << std::endl;
                continue;
            }

            if (is_admin(username)) {
                std::string contents = command_cat_admin(dir[0], splits[1], curr_dir_hashed, key_name);
                std::cout << contents << std::endl;
            } else {
                std::string contents = command_cat(username, splits[1], curr_dir_hashed, key_name);
                std::cout << contents << std::endl;
            }
        } else if (splits[0] == "mkfile") {
            if (splits.size() < 3 || splits[2].empty()) {
                std::cout << "Filename and file contents cannot be empty" << std::endl;
                continue;
            }

            std::string curr_dir;
            std::string curr_dir_hashed;
            for (const std::string& str:dir) {
                curr_dir.append(str);
                curr_dir_hashed.append(auth::hash(str));
                curr_dir.append("/");
                curr_dir_hashed.append("/");
            }

            if (is_admin(username)) {
                std::cout << "Sorry, admin cannot create files" << std::endl;
                continue;
            }

            if (curr_dir.empty() || curr_dir.rfind("shared", 0) == 0) {
                std::cout << "Forbidden" << std::endl;
                continue;
            }

            if (splits[1].find("_publickey", 0) != std::string::npos || splits[1].find("_privatekey", 0) != std::string::npos || (splits[1].find("..", 0) != std::string::npos)) {
                std::cout << "Forbidden" << std::endl;
                continue;
            }

            size_t pos = user_command.find(" ", user_command.find(" ") + 1);
            std::string file_contents = user_command.substr(pos + 1);

            if (strlen(file_contents.c_str()) > 300) {
                std::cout << "Max file content allowed is 300 characters" << std::endl;
                continue;
            }

            command::mkfile(username, splits[1], curr_dir_hashed, file_contents);
        } else if (user_command.rfind("adduser", 0) == 0) {
            if (!is_admin(username)) {
                std::cout << "Forbidden. Only Admin can perform adduser command." << std::endl;
                continue; 
            }
            size_t pos = user_command.find(" ");
            if (pos == -1) {
                // to counter malicious input: adduser
                std::cout << "No new username provided." << std::endl;
                continue;
            }
            std::string new_username = user_command.substr(pos+1, -1);
            if (new_username == "") {
                // to counter malicious input: adduser 
                std::cout << "No new username provided." << std::endl;
                continue;
            }
            if (new_username.length() > 10) {
                std::cout << "Invalid new username. Maximum 10 characters." << std::endl;
                continue;
            }
            if (strcasecmp(new_username.c_str(),"admin") == 0) {
                std::cout << "Invalid new username: " << new_username << std::endl;
                continue;
            }
            if (!check_invalid_username(new_username)) {
                std::cout << "Invalid new username. Only alphabets and numbers are allowed in a username." << std::endl;
                continue;
            }
            struct stat st;
            std::string root_folder_path = "filesystem/" + auth::hash(new_username);
            if (stat(&root_folder_path[0], &st) != -1) {
                std::cout << "User " << new_username << " already exists" << std::endl;
                continue;
            }
            //passed all exception checks, now we create new user
            command::adduser(new_username);
        } else {
            std::cout << "Invalid command." << std::endl;
        }
    }
}

