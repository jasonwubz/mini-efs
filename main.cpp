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
            std::cout << "Initial setup finished. Fileserver closed. Admin now can login using the admin keyfile" << std::endl;
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
        std::vector<std::string> arguments = command::parse_command(command);

        try {
            if (command == "") {
                continue;
            } else if (command == "help") {
                command::help(currentUser);
            } else if (command == "exit") {
                std::cout << "Fileserver closed. Goodbye " << currentUser.username << " :)" << std::endl;
                return 0;
            } else if (command == "pwd") {
                std::cout << command::pwd(dir) << std::endl;
            } else if (command == "cd") {
                command::cd(currentUser, dir, arguments);
            } else if (command == "ls") {
                command::ls(currentUser, dir);
            } else if (command == "mkdir") {
                command::makedir(currentUser, dir, arguments);
            } else if (command == "share") {
                command::share(currentUser, dir, arguments);
            } else if (command == "cat") {
                std::string contents = command::cat(currentUser, dir, arguments);
                std::cout << contents << std::endl;
            } else if (command == "mkfile") {
                command::mkfile(currentUser, dir, arguments);
            } else if (command == "adduser") {
                command::adduser(currentUser, arguments);
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
