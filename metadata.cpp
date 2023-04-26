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

// Write key: value pair to metadata file
void metadata::write(std::string key, std::string value)
{
    const std::string filename = "metadata.json";
    std::ifstream ifs(filename);
    Json::Value metadata;
    Json::CharReaderBuilder builder;
    JSONCPP_STRING err;
    Json::parseFromStream(builder, ifs, &metadata, &err);
    
    // Add a new key-value pair to the Json::Value object
    metadata[key] = value;

    // Write the modified Json::Value object back to the JSON file
    std::ofstream ofs(filename);
    Json::StreamWriterBuilder writerBuilder;
    std::unique_ptr<Json::StreamWriter> writer(writerBuilder.newStreamWriter());
    writer->write(metadata, &ofs);
    ifs.close();
    ofs.close();
}

int metadata::setup(std::string salt, std::string filename)
{
    Json::Value metadata;
    std::ofstream ofs(filename);
    Json::StreamWriterBuilder writerBuilder;
    std::unique_ptr<Json::StreamWriter> writer(writerBuilder.newStreamWriter());

    metadata["salt"] = salt;

    return writer->write(metadata, &ofs);
}

// Read metadata.json, use hash as key to get back original value
std::string metadata::get(std::string hash)
{
    std::ifstream ifs("metadata.json");
    Json::Value metadata;
    Json::CharReaderBuilder builder;
    JSONCPP_STRING err;
    Json::parseFromStream(builder, ifs, &metadata, &err);

    return metadata[hash].asString();
}