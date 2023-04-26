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
    void help(auth::User &currentUser);
    void ls(auth::User &currentUser, std::vector<std::string> &dir);
    void adduser(auth::User &currentUser, std::string username);
    std::string pwd(std::vector<std::string> &dir);
    void cd(auth::User &currentUser, std::vector<std::string> &dir, std::string change_dir, std::string username);
    void makedir(auth::User &currentUser, std::vector<std::string> &dir, std::string new_dir, std::string username);
    void mkfile(auth::User &currentUser, const std::string &filename, const std::string &curr_dir, const std::string &contents);
    void sharefile(auth::User &currentUser, std::string username, std::string key_name, std::vector<std::string> &dir, std::string user_command);
    std::string cat(auth::User &currentUser, const std::string &username, const std::string &filename, const std::string &curr_dir, const std::string &key_name);
}

#endif