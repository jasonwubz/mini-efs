#include <command.h>
#include <auth.h>
#include <cstdlib>
#include <string>
#include <ostream>
#include <vector>
#include <iostream>
#include <filesystem>
#include <sys/types.h>

void command::adduser(std::string new_username) {
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

void command::show_help(bool is_admin)
{
    std::cout << std::endl;
    std::cout << "Available commands:" << std::endl;
    std::cout << "-------------------" << std::endl;

    std::cout << "cd <directory>                   - Change directory" << std::endl;
    std::cout << "pwd                              - Print the current directory" << std::endl;
    std::cout << "ls                               - List the files and directories in the current directory" << std::endl;
    std::cout << "cat <filename>                   - Print content of the given filename" << std::endl;
    

    if (is_admin) {
        std::cout << "adduser <username>               - Add new user by given username" << std::endl;
    } else {
        std::cout << "share <filename> <username>      - Share the file <filename> with the target user <username>" << std::endl;
        std::cout << "mkfile <filename> <contents>     - Create a new file <filename> with the ascii printable contents <contents>" << std::endl;
    }

    std::cout << "exit                             - Terminate the program" << std::endl;
}