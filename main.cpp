#include <src/auth.h>
#include <src/command.h>
#include <src/metadata.h>
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
    std::string command;
    auth::User currentUser;
    std::vector<std::string> dir;

    if (argc != 2) {
        std::cerr << "Wrong command to start the fileserver. You should use command: " << std::endl;
        std::cerr << "./fileserver key_name" << std::endl;
        return 1;
    }

    std::cout << "--------------------------------------------------------" << std::endl;
    std::cout << "     You are accessing Encrypted Secure File System     " << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl << std::endl;

    try {
        std::string key_name = argv[1];
        int validateResult = auth::validate(key_name, currentUser);
        if (validateResult == 0) {
            std::cout << "Welcome! Logged in as " << currentUser.username << std::endl;
            command::help(currentUser);
        } else if (validateResult == 1) {
            std::cout << "Setting up environment..." << std::endl << std::endl;
            std::cout << "Admin Public/Private key pair has been created." << std::endl;
            std::cout << "Your private key_name is " << key_name << std::endl;
            std::cout << "Please store your key_name safely. Admin can login by command: " << std::endl;
            std::cout << "./fileserver " << key_name << std::endl << std::endl;
            std::cout << "Initial setup finshed, Fileserver closed. Admin now can login using the admin keyfile" << std::endl;
            return 0;
        } else {
            std::cerr << "Unexpected error during authentication" << std::endl;
            return 1;
        }
    } catch (auth::AuthException a) {
        std::cerr << a.what() << std::endl;
        return 1;
    }

    while (true) {
        std::cout << std::endl;
        std::cout << "> ";
        getline(std::cin, command);
        std::vector<std::string> splits = split_string(command, " ");

        try {
            if (command == "help") {
                command::help(currentUser);
            } else if (command == "exit") {
                std::cout << "Fileserver closed. Goodbye " << currentUser.username << " :)" << std::endl;
                return 0;
            } else if (command == "pwd") {
                std::cout << command::pwd(dir) << std::endl;
            } else if (command.substr(0, 2) == "cd" && command.substr(2, 1) == " ") {
                command::cd(currentUser, dir, command.substr(3));
            } else if (command == "ls") {
                command::ls(currentUser, dir);
            } else if (command.substr(0,5) == "mkdir" && command.substr(5,1) == " " && !isWhitespace(command.substr(6)) ) {
                command::makedir(currentUser, dir, command.substr(6));
            } else if (command.rfind("share", 0) == 0) {
                command::sharefile(currentUser, dir, command);
            } else if (splits[0] == "cat") {
                std::string contents = command::cat(currentUser, splits[1], dir, splits);
                std::cout << contents << std::endl;
            } else if (splits[0] == "mkfile") {
                size_t pos = command.find(" ", command.find(" ") + 1);
                std::string file_contents = command.substr(pos + 1);
                command::mkfile(currentUser, dir, file_contents, splits);
            } else if (command.rfind("adduser", 0) == 0 && command.find(" ") != -1) {
                std::string new_username = command.substr(command.find(" ")+1, -1);
                command::adduser(currentUser, new_username);
            } else {
                std::cerr << "Invalid command." << std::endl;
            }
        } catch (command::CommandException c) {
            std::cerr << c.what() << std::endl;
            continue;
        } catch (auth::AuthException a) {
            std::cerr << a.what() << std::endl;
            continue;
        }
    }

    return 0;
}
