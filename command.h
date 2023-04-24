#ifndef MINIIEFS_CMD
#define MINIIEFS_CMD

#include <cstdlib>
#include <openssl/rsa.h>
#include <string>
#include <vector>
#include <sys/types.h>


namespace command
{
    void show_help(bool is_admin);
    void ls(std::vector<std::string>&dir, std::string username);
    void adduser(std::string new_username);
}

#endif