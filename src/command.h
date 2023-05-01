#ifndef MINIEFS_CMD
#define MINIEFS_CMD

#include <src/auth.h>
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
    void adduser(auth::User &currentUser, const std::vector<std::string> &arguments);
    std::string pwd(std::vector<std::string> &dir);
    void cd(auth::User &currentUser, std::vector<std::string> &dir, const std::vector<std::string> &arguments);
    void makedir(auth::User &currentUser, std::vector<std::string> &dir, const std::vector<std::string> &arguments);
    void mkfile(auth::User &currentUser, std::vector<std::string> &dir, const std::vector<std::string> &arguments);
    void share(auth::User &currentUser, std::vector<std::string> &dir, const std::vector<std::string> &arguments);
    std::string cat(auth::User &currentUser, std::vector<std::string> &dir, const std::vector<std::string> &arguments);
    std::vector<std::string> parse_command(std::string &rawCommand);
}

#endif