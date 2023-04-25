#ifndef MINIIEFS_CMD
#define MINIIEFS_CMD

#include <cstdlib>
#include <openssl/rsa.h>
#include <string>
#include <vector>
#include <sys/types.h>

namespace command
{
    void help(bool is_admin);
    void ls(std::vector<std::string>&dir, std::string username);
    void adduser(std::string new_username);
    std::string pwd(std::vector<std::string>& dir);
    void cd(std::vector<std::string>& dir, std::string change_dir, std::string username);
    void makedir(std::vector<std::string>& dir, std::string new_dir, std::string username);
}

#endif