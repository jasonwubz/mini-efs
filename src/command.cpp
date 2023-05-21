#include <src/command.h>
#include <src/metadata.h>
#include <src/auth.h>
#include <cstdlib>
#include <unistd.h>
#include <string.h>
#include <ostream>
#include <vector>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <regex>
#include <sys/types.h>
#include <sys/stat.h>

// from https://stackoverflow.com/questions/1798112/removing-leading-and-trailing-spaces-from-a-string
std::string trim(const std::string &str, const std::string &whitespace = " \t")
{
    const auto strBegin = str.find_first_not_of(whitespace);
    if (strBegin == std::string::npos) {
        return ""; // no content
    }

    const auto strEnd = str.find_last_not_of(whitespace);
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}

std::vector<std::string> command::parse_command(std::string &rawCommand)
{
    std::vector<std::string> parsedArguments;
    rawCommand = trim(rawCommand);

    if (rawCommand.rfind("share", 0) == 0) {
        std::regex regex("^share\\s+((\"|')?([A-Za-z0-9\\-_\\s.]+)(\\2)|([A-Za-z0-9\\-_.]+))\\s+([A-Za-z0-9_]+)");
        std::smatch matches;
        if (regex_search(rawCommand, matches, regex)) {
            std::string tempParameter;
            for (size_t i = 0; i < matches.size(); ++i) {
                tempParameter = matches[i].str();
                if ((i == 3 || i == 5) && tempParameter.length() > 0) {
                    // filename
                    parsedArguments.push_back(trim(tempParameter));
                }
                if (i == 6) {
                    // target username
                    parsedArguments.push_back(trim(tempParameter));
                }
            }
        }
        rawCommand = "share";
    } else if (rawCommand.rfind("mkdir", 0) == 0) {
        std::regex regex("^mkdir\\s+((\"|')?([A-Za-z0-9\\-_\\s.]+)(\\2)|([A-Za-z0-9\\-_.]+))");
        std::smatch matches;
        if (regex_search(rawCommand, matches, regex)) {
            std::string tempParameter;
            for (size_t i = 0; i < matches.size(); ++i) {
                tempParameter = matches[i].str();
                if ((i == 3 || i == 5) && tempParameter.length() > 0) {
                    // directory name
                    parsedArguments.push_back(trim(tempParameter));
                }
            }
        }
        rawCommand = "mkdir";
    } else if (rawCommand.rfind("cd", 0) == 0) {
        std::regex regex("^cd\\s+(.*)");
        std::smatch matches;
        if (regex_search(rawCommand, matches, regex)) {
            std::string tempParameter;
            for (size_t i = 0; i < matches.size(); ++i) {
                tempParameter = matches[i].str();
                if (i == 1) {
                    // cd string
                    parsedArguments.push_back(trim(tempParameter));
                }
            }
        }
        rawCommand = "cd";
    } else if (rawCommand.rfind("cat", 0) == 0) {
        std::regex regex("^cat\\s+((\"|')?([A-Za-z0-9\\-_\\s.]+)(\\2)|([A-Za-z0-9\\-_.]+))");
        std::smatch matches;
        if (regex_search(rawCommand, matches, regex)) {
            std::string tempParameter;
            for (size_t i = 0; i < matches.size(); ++i) {
                tempParameter = matches[i].str();
                if ((i == 3 || i == 5) && tempParameter.length() > 0) {
                    // filename
                    parsedArguments.push_back(trim(tempParameter));
                }
            }
        }
        rawCommand = "cat";
    } else if (rawCommand.rfind("mkfile", 0) == 0) {
        std::regex regex("^mkfile\\s+((\"|')?([A-Za-z0-9\\-_\\s.]+)(\\2)|([A-Za-z0-9\\-_.]+))\\s+(.*)");
        std::smatch matches;
        if (regex_search(rawCommand, matches, regex)) {
            std::string tempParameter;
            for (size_t i = 0; i < matches.size(); ++i) {
                tempParameter = matches[i].str();
                if ((i == 3 || i == 5) && tempParameter.length() > 0) {
                    // filename
                    parsedArguments.push_back(trim(tempParameter));
                }
                if (i == 6) {
                    // content
                    parsedArguments.push_back(trim(tempParameter));
                }
            }
        }
        rawCommand = "mkfile";
    } else if (rawCommand.rfind("adduser", 0) == 0) {
        std::regex regex("^adduser\\s+([A-Za-z0-9_]+)");
        std::smatch matches;
        if (regex_search(rawCommand, matches, regex)) {
            std::string tempParameter;
            for (size_t i = 0; i < matches.size(); ++i) {
                tempParameter = matches[i].str();
                if ((i == 1) && tempParameter.length() > 0) {
                    // username
                    parsedArguments.push_back(trim(tempParameter));
                }
            }
        }
        rawCommand = "adduser";
    }

    return parsedArguments;
}

command::CommandException::CommandException(std::string msg)
{
     message = msg;
}

std::string command::CommandException::what()
{
    return message;
}

bool _validate_username(std::string username)
{
    for (int i=0; i<username.length(); i++) {
        if (!std::isalpha(username[i]) && !std::isdigit(username[i])) {
            return false;
        }
    }
    return true;
}

void command::adduser(auth::User &currentUser, const std::vector<std::string> &arguments)
{
    if (arguments.size() == 0) {
        throw command::CommandException("Please provide the username");
    }

    std::string username = arguments[0];

    if (!currentUser.isAdmin) {
        throw command::CommandException("Forbidden. Only Admin can perform adduser command.");
    }
    
    if (username == "") {
        throw command::CommandException("No new username provided.");
    }
    if (username.length() > 10) {
        throw command::CommandException("Invalid new username. Maximum 10 characters.");
    }
    if (auth::is_admin(username)) {
        throw command::CommandException("Invalid new username: " + username);
    }
    if (!_validate_username(username)) {
        throw command::CommandException("Invalid new username. Only alphabets and numbers are allowed in a username.");
    }
    struct stat st;
    std::string root_folder_path = auth::AUTH_DIR_FILESYSTEM + "/" + auth::hash(username);
    if (stat(&root_folder_path[0], &st) != -1) {
        throw command::CommandException("User " + username + " already exists");
    }
    
    // passed all exception checks, now we create new user
    int result = auth::user_setup(username);
    if (result) {
        throw command::CommandException("Error adding user");
    }

    std::string randomKey = auth::csprng();
    if (randomKey.length() == 0) {
        throw command::CommandException("Error adding user");
    }
    std::string keyName = username + "_" + randomKey;
    
    auth::create_keypair(keyName);
    std::cout << "User " << username << " Public/Private key pair has been created." << std::endl;
    std::cout << "The private key_name is " << keyName << std::endl;
    std::cout << "Please give this key_name to user and let user know that it must be remained secret to him/herself only." << std::endl;
    std::cout << "User " << username << " can login by command: " << std::endl;
    std::cout << "./fileserver " << keyName << std::endl << std::endl;
}

void command::ls(auth::User &currentUser, std::vector<std::string> &dir)
{
    // construct current directory string
    std::string currentDirectory;
    bool hasUpperDirectory = false;
    std::cout << "d -> ."<< std::endl;
    
    if (currentUser.isAdmin) {
        currentDirectory = std::filesystem::current_path().string() + "/" + auth::AUTH_DIR_FILESYSTEM + "/";
    } else{
        currentDirectory = std::filesystem::current_path().string() + "/" + auth::AUTH_DIR_FILESYSTEM + "/" + currentUser.usernameHashed;
    }
    for (std::string str : dir) {
        if (!str.empty()) {
            currentDirectory = currentDirectory + "/" + auth::hash(str);
            hasUpperDirectory = true;
        }
    }
    if (hasUpperDirectory) {
        std::cout << "d -> .." << std::endl;
    }
    
    // iterate directory
    const std::filesystem::path path = std::filesystem::u8path(currentDirectory); // sanity check for encoding
    for (const auto &entry : std::filesystem::directory_iterator(path)) {
        std::string prefix;
        std::string displayName;
        std::string entryPath = entry.path();
        std::string subPath = entryPath.substr(currentDirectory.length());
        if (std::filesystem::is_directory(std::filesystem::status(entryPath))) {
            prefix = "d -> ";
        } else {
            prefix = "f -> ";
        }
        
        if (subPath[0] == '/') {
            displayName = metadata::get(entryPath.substr(currentDirectory.length() + 1));
        } else {
            displayName = metadata::get(entryPath.substr(currentDirectory.length()));
        }
        if (displayName != "") {
            std::cout << prefix + displayName << std::endl;
        }
    }
}

void command::help(auth::User &currentUser)
{
    std::cout << std::endl;
    std::cout << "Available commands:" << std::endl;
    std::cout << "-------------------" << std::endl;

    std::cout << "cd <directory>               - Change directory" << std::endl;
    std::cout << "pwd                          - Print the current directory" << std::endl;
    std::cout << "ls                           - List the files and directories in the current directory" << std::endl;
    std::cout << "cat <filename>               - Print content of the given filename" << std::endl;

    if (currentUser.isAdmin) {
        std::cout << "adduser <username>           - Add new user by given username" << std::endl;
    } else {
        std::cout << "share <filename> <username>  - Share the file <filename> with the target user <username>" << std::endl;
        std::cout << "mkfile <filename> <contents> - Create a new file <filename> with the ascii printable contents <contents>" << std::endl;
    }

    std::cout << "exit                         - Terminate the program" << std::endl;
    std::cout << "help                         - This help page" << std::endl;
}

std::string command::pwd(std::vector<std::string> &dir)
{
    std::string result;
    if (dir.empty()) {
        return "/";
    }

    for (std::string str:dir) {
        result += "/" + str;
    }

    return result;
}

void command::cd(auth::User &currentUser, std::vector<std::string> &dir, const std::vector<std::string> &arguments)
{
    if (arguments.size() == 0) {
        throw command::CommandException("Please provide cd path");
    }

    std::string changeDirectory = arguments[0];
    std::stringstream test(changeDirectory);
    std::string segment;
    std::vector<std::string> seglist;
    std::vector<std::string> new_dir;

    // split input by '/'
    while (getline(test, segment, '/')) {
        seglist.push_back(segment);
    }
    
    // if the input started by "." or "..", use the current directory for prefix
    if (seglist[0] == "." || seglist[0] == ".." || !seglist[0].empty()) {
        new_dir = dir;
    }
    
    // build new directory
    for (std::string seg : seglist) {
        if (seg == "." || seg.empty()) {
            continue;
        } else if (seg == "..") {
            if (new_dir.empty()) {
                throw command::CommandException("Invalid directory!");
            }
            new_dir.pop_back();
        } else {
            new_dir.push_back(seg);
        }
    }

    // convert new directory to string in order to use std::filesystem functions
    std::string check_dir = std::filesystem::current_path().string() + "/" + auth::AUTH_DIR_FILESYSTEM ;
    if (!currentUser.isAdmin) {
        check_dir = check_dir + "/" + currentUser.usernameHashed;
    }
    for (std::string str : new_dir) {
        if (!str.empty()) {
            check_dir = check_dir + "/" + auth::hash(str);
        }
    }
    if (std::filesystem::is_directory(std::filesystem::status(check_dir)) ) {
        dir = new_dir;
        std::cout << "Directory changed to: ";
        std::cout << command::pwd(dir) << std::endl; 
    } else {
        throw command::CommandException("Invalid directory!");
    }

    return;
}

void command::makedir(auth::User &currentUser, std::vector<std::string>& dir, const std::vector<std::string> &arguments)
{
    if (arguments.size() == 0) {
        throw command::CommandException("Please provide directory name");
    }

    if (currentUser.isAdmin) {
        throw command::CommandException("Invalid command for admin!");
    }

    std::string cur_dir;
    for (std::string str:dir) {
        cur_dir = cur_dir + '/' + auth::hash(str);
    }

    std::string newDirectory = arguments[0];

    if (newDirectory.find(".") != -1 or newDirectory.find("..") != -1 or newDirectory.find("/") != -1) {
        throw command::CommandException("Invalid directory name.");
    }

    if (dir.empty()) {
        throw command::CommandException("Forbidden");
    }

    if (cur_dir.substr(1,65).rfind(auth::hash("shared"), 0) == 0) {
        throw command::CommandException("Forbidden: Cannot create directory in /shared");
    }

    std::string newDirectoryHashed = auth::hash(newDirectory);
    metadata::write(newDirectoryHashed, newDirectory);
    std::string newFullPath = std::filesystem::current_path().string() + "/" + auth::AUTH_DIR_FILESYSTEM + "/" + currentUser.usernameHashed + '/' + cur_dir.substr(1) + '/' + newDirectoryHashed;

    char *dirname = strdup(newFullPath.c_str());
    if (mkdir(dirname, AUTH_DIR_PERMISSION) == -1) {
        throw command::CommandException("Error: directory exists.");
    } else {
        std::cout << "Directory created" << std::endl;
    }
    free(dirname);
}

void command::mkfile(auth::User &currentUser, std::vector<std::string> &dir, const std::vector<std::string> &arguments)
{
    if (arguments.size() < 2) {
        throw command::CommandException("Please provide filename and content");
    }

    std::string contents = arguments[1];

    if (currentUser.isAdmin) {
        throw command::CommandException("Sorry, admin cannot create files");
    }

    std::string filename = arguments[0];
    std::string logicalPath;
    std::string physicalPath;
    for (const std::string &str:dir) {
        logicalPath.append(str);
        physicalPath.append(auth::hash(str));
        logicalPath.append("/");
        physicalPath.append("/");
    }

    if (logicalPath.empty() || logicalPath.rfind("shared", 0) == 0) {
        throw command::CommandException("Forbidden");
    }

    if (
        filename.find("_publickey", 0) != std::string::npos ||
        filename.find("_privatekey", 0) != std::string::npos ||
        (filename.find("..", 0) != std::string::npos)
    ) {
        throw command::CommandException("Forbidden");
    }

    // TEMP: increase the size limit because we can now handle chunks
    if (strlen(contents.c_str()) > (AUTH_MAX_CHUNK_SIZE * 100)) {
        throw command::CommandException("Max file content allowed is " + std::to_string(AUTH_MAX_CHUNK_SIZE) + " characters");
    }

    std::string physicalFilename = auth::hash(filename);
    metadata::write(physicalFilename, filename);
    std::string savePath = auth::AUTH_DIR_FILESYSTEM + "/" + currentUser.usernameHashed + "/" + physicalPath + physicalFilename;

    char *contentsCopy = new char[contents.length() + 1];
    strcpy(contentsCopy, contents.c_str());

    if (currentUser.encryptSave(contentsCopy, savePath) == -1) {
        throw command::CommandException("An error occurred during encryption");
    }

    // check for expected shared file and update it
    std::string expectedSuffix = "/" + auth::hash("shared") + "/" + currentUser.usernameHashed + "/" + physicalFilename;

    for (const auto &entry : std::filesystem::directory_iterator(auth::AUTH_DIR_FILESYSTEM)) {
        std::string entryPath = entry.path();
        std::string sharedUserName = metadata::get(entryPath.substr(auth::AUTH_DIR_FILESYSTEM.length() + 1)); // + 1 is for /
        entryPath += expectedSuffix;
        if (std::filesystem::exists(entryPath)) {
            auth::User sharedUser;
            sharedUser.set_user(sharedUserName);
            sharedUser.encryptSave(contentsCopy, entryPath);
        }
    }
    delete[] contentsCopy;

    std::cout << "File created successfully!" << std::endl;
}

// Get the raw content of a file
char *_get_raw_content(std::string path, int &fSize)
{
    char *fileContent;

    std::ifstream ifs;
    ifs.open(path);

    if (!(ifs && ifs.is_open())) {
        throw command::CommandException("File does not exists");
    }
    ifs.seekg(0, std::ios::end);
    fSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    fileContent = new char[fSize];
    ifs.read(fileContent, fSize);
    ifs.close();

    return fileContent;
}

void command::share(auth::User &currentUser, std::vector<std::string>& dir, const std::vector<std::string> &arguments)
{
    // check who is the username
    if (currentUser.isAdmin) {
        throw command::CommandException("Forbidden");
    }

    if (arguments.size() < 2 ) {
        throw command::CommandException("Please provide filename and username");
    }

    // check file exists by reading it
    std::string hashed_pwd;
    for (int i = 0; i < dir.size(); i++) {
        std::string hashed_dir = auth::hash(dir[i]);
        hashed_pwd += "/" + hashed_dir;
    }

    std::string filenameHashed = auth::hash(arguments[0]);
    std::string targetUsername = arguments[1];
    std::string filepath = auth::AUTH_DIR_FILESYSTEM + "/" + currentUser.usernameHashed + hashed_pwd + "/" + filenameHashed;

    struct stat s;
    if (
        (stat(filepath.c_str(), &s)) == 0 &&
        (s.st_mode & S_IFDIR)
    ) {
        throw command::CommandException("Cannot share a directory, please enter a file name");
    }

    int rSize;
    char *rawContent = _get_raw_content(filepath, rSize);

    // check that the user cannot share to themselves
    if (targetUsername == currentUser.username) {
        throw command::CommandException("You cannot share files to yourself.");
    }

    auth::User targetUser;
    targetUser.set_user(targetUsername);
    
    std::string private_key_path = auth::AUTH_DIR_FILESYSTEM + "/" + currentUser.usernameHashed + "/" + auth::hash(currentUser.keyName + "_privatekey");
    if (private_key_path == filepath) {
        throw command::CommandException("You cannot share your private key.");
    }

    // check that target username exists (a valid user have a public key)
    if (targetUser.get_key(AUTH_KEY_TYPE_PUBLIC) == NULL) {
        throw command::CommandException("User '" + targetUsername + "' does not exists.");
    }

    // decrypt file for copying
    char *decryptedContent;
    try {
        decryptedContent = currentUser.decrypt(rawContent, rSize);
    } catch (auth::AuthException a) {
        throw command::CommandException("An error occured while attempting to share file");
    }

    // Create directory if it doesn't exist
    std::string targetDirectory = auth::AUTH_DIR_FILESYSTEM + "/" + targetUser.usernameHashed + "/" + auth::hash("shared") + "/" + currentUser.usernameHashed;
    if (!std::filesystem::is_directory(std::filesystem::status(targetDirectory))) {
        if (mkdir(&targetDirectory[0], AUTH_DIR_PERMISSION) != 0) {
            throw command::CommandException("An error occurred during file share");
        }
    }

    // now encrypt and save new file
    std::string targetPath = targetDirectory + "/" + filenameHashed;
    if (targetUser.encryptSave(decryptedContent, targetPath) == -1) {
        throw command::CommandException("An error occurred during file share");
    }
    
    free(decryptedContent);
    delete[] rawContent;

    std::cout << "File has been successfully shared" << std::endl;
}

std::string command::cat(auth::User &currentUser, std::vector<std::string> &dir,  const std::vector<std::string> &arguments)
{
    if (arguments.size() == 0 ) {
        throw command::CommandException("Please provide filename");
    }

    std::string filename = arguments[0];
    std::string filenameHashed = auth::hash(filename);
    std::string fullPath;

    std::string logicalPath;
    std::string physicalPath;
    for (const std::string& s:dir) {
        logicalPath.append(s);
        physicalPath.append(auth::hash(s));
        logicalPath.append("/");
        physicalPath.append("/");
    }

    if (logicalPath.empty()) {
        throw command::CommandException("Forbidden");
    }

    if (
        (filename.find("_publickey", 0) != std::string::npos) ||
        (filename.find("_privatekey", 0) != std::string::npos) ||
        (filename.find("..", 0) != std::string::npos)
    ) {
        throw command::CommandException("Forbidden");
    }
    
    std::string catUsername = currentUser.username;
    if (currentUser.isAdmin) {
        catUsername = dir[0];
    }
    
    if (currentUser.isAdmin) {
        fullPath = auth::AUTH_DIR_FILESYSTEM + "/" + physicalPath + filenameHashed;
    } else {
        fullPath = auth::AUTH_DIR_FILESYSTEM + "/" + auth::hash(catUsername) + "/" + physicalPath + filenameHashed;
    }

    struct stat s;
    if (
        (stat(fullPath.c_str(), &s) == 0) &&
        (s.st_mode & S_IFDIR)
    ) {
        throw command::CommandException("Cannot open a directory, please enter a file name");
    }

    int rSize;
    char *rawContent = _get_raw_content(fullPath, rSize);
    char *decryptedContent;

    if (currentUser.isAdmin) {
        auth::User catUser;
        catUser.set_user(catUsername);
        decryptedContent = catUser.decrypt(rawContent, rSize);
    } else {
        decryptedContent = currentUser.decrypt(rawContent, rSize);
    }

    std::string output = decryptedContent;
    free(decryptedContent);
    delete[] rawContent;
    return output;
}