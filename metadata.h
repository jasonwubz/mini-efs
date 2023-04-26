#ifndef MINIEFS_META
#define MINIEFS_META

#include <cstdlib>
#include <string>
#include <vector>

namespace metadata
{
    void write(std::string key, std::string value);
    int setup(std::string salt, std::string filename = "metadata.json");
    std::string get(std::string key);
}

#endif