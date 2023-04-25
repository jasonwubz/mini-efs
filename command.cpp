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

void command::adduser(std::string new_username)
{
    // create user folders
    int result = auth::user_folder_setup(new_username);
    if (result) {
        return;
    }

    // create users RSA public key and private keys (2 copies)
    std::string random_byte_hex = auth::csprng();
    if (random_byte_hex.length() == 0) {
        return;
    }
    std::string key_name = new_username + "_" + random_byte_hex;
    auth::create_RSA(key_name);
    std::cout << "User " << new_username << " Public/Private key pair has been created." << std::endl;
    std::cout << "The private key_name is " << key_name << std::endl;
    std::cout << "Please give this key_name to user and let user know that it must be remained secret to him/herself only." << std::endl;
    std::cout << "User " << new_username << " can login by command: " << std::endl;
    std::cout << "./fileserver " << key_name << std::endl << std::endl;
}

void command::ls(std::vector<std::string>&dir, std::string username)
{
    // construct current directory string
    std::string cur_dir;
    bool upper_dir = false;
    std::cout << "d -> ."<< std::endl;
    
    if (username == "Admin") {
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

void command::help(bool is_admin)
{
    std::cout << std::endl;
    std::cout << "Available commands:" << std::endl;
    std::cout << "-------------------" << std::endl;

    std::cout << "cd <directory>               - Change directory" << std::endl;
    std::cout << "pwd                          - Print the current directory" << std::endl;
    std::cout << "ls                           - List the files and directories in the current directory" << std::endl;
    std::cout << "cat <filename>               - Print content of the given filename" << std::endl;
    

    if (is_admin) {
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
    if (username != "Admin") {
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
                if (mkdir(dirname, 0744) == -1) {
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