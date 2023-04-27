#ifndef MINIEFS_META
#define MINIEFS_META

#include <cstdlib>
#include <string>
#include <vector>

namespace metadata
{
    extern const std::string META_FILENAME;

    void write(std::string key, std::string value);
    int setup(std::string salt);
    std::string get(std::string key);
}

#endif