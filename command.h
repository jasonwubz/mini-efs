#ifndef MINIEFS_CMD
#define MINIEFS_CMD

#include <auth.h>
#include <cstdlib>
#include <openssl/rsa.h>
#include <string>
#include <vector>
#include <sys/types.h>

namespace command
{
    class CommandException : public std::exception {
        private:
            std::string message;
        public:
            CommandException(std::string msg);
            std::string what();
    };

    void help(auth::User &currentUser);
    void ls(auth::User &currentUser, std::vector<std::string> &dir);
    void adduser(auth::User &currentUser, std::string username);
    std::string pwd(std::vector<std::string> &dir);
    void cd(auth::User &currentUser, std::vector<std::string> &dir, std::string change_dir);
    void makedir(auth::User &currentUser, std::vector<std::string> &dir, std::string new_dir);
    void mkfile(auth::User &currentUser, std::vector<std::string> &dir, const std::string &contents, const std::vector<std::string> &commands);
    void sharefile(auth::User &currentUser, std::vector<std::string> &dir, std::string user_command);
    std::string cat(auth::User &currentUser, const std::string &filename, std::vector<std::string> &dir, const std::vector<std::string> &commands);
}

#endif