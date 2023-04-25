#include <metadata.h>
#include <cstdlib>
#include <string.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <sys/stat.h>
#include <jsoncpp/json/json.h>

// In mkfile and mkdir, we need to calculate the key: value pair and store it in metadata.json
void metadata::write(std::string key, std::string value)
{
    std::ifstream ifs("metadata.json");
    Json::Value metadata;
    Json::CharReaderBuilder builder;
    JSONCPP_STRING err;
    Json::parseFromStream(builder, ifs, &metadata, &err);
    
    // Add a new key-value pair to the Json::Value object
    metadata[key] = value;

    // Write the modified Json::Value object back to the JSON file
    std::ofstream ofs("metadata.json");
    Json::StreamWriterBuilder writerBuilder;
    std::unique_ptr<Json::StreamWriter> writer(writerBuilder.newStreamWriter());
    writer->write(metadata, &ofs);
}