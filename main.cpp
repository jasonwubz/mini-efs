#include <auth.h>
#include <command.h>
#include <metadata.h>
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

#define DIR_PERMISSION 0744

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

bool check_invalid_username(std::string username)
{
    for (int i=0;i<username.length();i++) {
        if (!std::isalpha(username[i]) && !std::isdigit(username[i])) {
            return false;
        }
    }
    return true;
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
    std::string user_command, key_name;
    auth::User currentUser;

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

        if (auth::initial_setup() == 1) {
            return 1;
        }

        metadata::write(auth::hash("personal"), "personal");
        metadata::write(auth::hash("shared"), "shared");

        std::string username = "admin";
        std::string randomKey = auth::csprng();
        if (randomKey.length() == 0) {
            return 1;
        }
        std::string key_name = username + "_" + randomKey;

        auth::create_RSA(key_name);
        std::cout << "Admin Public/Private key pair has been created." << std::endl;
        std::cout << "Your private key_name is " << key_name << std::endl;
        std::cout << "Please store your key_name safely. Admin can login by command: " << std::endl;
        std::cout << "./fileserver " << key_name << std::endl << std::endl;

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
            std::string username = key_name.substr(0,pos);
            currentUser.set_user(username);
            std::cout << "Welcome! Logged in as " << username << std::endl;
            command::help(currentUser.isAdmin);
        }
    }

    std::vector<std::string> dir;
    
    while (true) {
        std::cout << std::endl;
        std::cout << "> ";
        getline(std::cin, user_command);
        std::vector<std::string> splits = split_string(user_command, " ");

        if (user_command == "exit") {
            std::cout << "Fileserver closed. Goodbye " << currentUser.username << " :)" << std::endl;
            return 0;
        } else if (user_command == "pwd") {
            std::cout << command::pwd(dir) << std::endl;
        } else if (user_command.substr(0, 2) == "cd" && user_command.substr(2, 1) == " ") {
            command::cd(dir, user_command.substr(3), currentUser.username);
        } else if (user_command == "ls") {
            command::ls(dir, currentUser.username);
        } else if (user_command.substr(0,5) == "mkdir" && user_command.substr(5,1) == " " && !isWhitespace(user_command.substr(6)) ) {
            command::makedir(dir, user_command.substr(6), currentUser.username);
        } else if (user_command.rfind("share", 0) == 0) {
            command::sharefile(currentUser.username, key_name, dir, user_command);
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
            
            std::string catUsername = currentUser.username;
            if (currentUser.isAdmin) {
                catUsername = dir[0];
            }
            std::string contents = command::cat(catUsername, splits[1], curr_dir_hashed, key_name);
            std::cout << contents << std::endl;
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

            if (currentUser.isAdmin) {
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

            command::mkfile(currentUser.username, splits[1], curr_dir_hashed, file_contents);
        } else if (user_command.rfind("adduser", 0) == 0) {
            if (!currentUser.isAdmin) {
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
