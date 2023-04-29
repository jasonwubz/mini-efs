#include <command.h>
#include <metadata.h>
#include <auth.h>
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

void command::adduser(auth::User &currentUser, std::string username)
{
    if (!currentUser.isAdmin) {
        throw command::CommandException("Forbidden. Only Admin can perform adduser command.");
    }
    
    if (username == "") {
        throw command::CommandException("No new username provided.");
    }
    if (username.length() > 10) {
        throw command::CommandException("Invalid new username. Maximum 10 characters.");
    }
    if (strcasecmp(username.c_str(), "admin") == 0) {
        throw command::CommandException("Invalid new username: " + username);
    }
    if (!_validate_username(username)) {
        throw command::CommandException("Invalid new username. Only alphabets and numbers are allowed in a username.");
    }
    struct stat st;
    std::string root_folder_path = "filesystem/" + auth::hash(username);
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
        currentDirectory = std::filesystem::current_path().string() + "/filesystem/";
    } else{
        currentDirectory = std::filesystem::current_path().string() + "/filesystem/" + currentUser.usernameHashed;
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

void command::cd(auth::User &currentUser, std::vector<std::string> &dir, std::string change_dir)
{
    std::stringstream test(change_dir);
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
    std::string check_dir = std::filesystem::current_path().string() + "/" + "filesystem";
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

void command::makedir(auth::User &currentUser, std::vector<std::string>& dir, std::string new_dir)
{
    if (currentUser.isAdmin) {
        throw command::CommandException("Invalid command for admin!");
    }

    std::string cur_dir;
    for (std::string str:dir) {
        cur_dir = cur_dir + '/' + auth::hash(str);
    }

    if (new_dir.find(".") != -1 or new_dir.find("..") != -1 or new_dir.find("/") != -1) {
        throw command::CommandException("Invalid directory name.");
    }

    if (dir.empty()) {
        throw command::CommandException("Forbidden");
    }

    if (cur_dir.substr(1,65) == auth::hash("shared")) {
        throw command::CommandException("Forbidden: Cannot create directory in /shared");
    } 

    metadata::write(auth::hash(new_dir),new_dir);
    new_dir = std::filesystem::current_path().string() + "/filesystem/" + currentUser.usernameHashed + '/' + cur_dir.substr(1) + '/' + auth::hash(new_dir);

    char *dirname = strdup(new_dir.c_str());
    if (mkdir(dirname, AUTH_DIR_PERMISSION) == -1) {
        throw command::CommandException("Error: directory exists.");
    } else {
        std::cout << "Directory created" << std::endl;
    }
    free(dirname);
}

void command::mkfile(auth::User &currentUser, std::vector<std::string> &dir, const std::string& contents, const std::vector<std::string> &commands)
{
    if (currentUser.isAdmin) {
        throw command::CommandException("Sorry, admin cannot create files");
    }

    if (commands.size() < 3 || commands[2].empty()) {
        throw command::CommandException("Filename and file contents cannot be empty");
    }

    std::string filename = commands[1];
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
        commands[1].find("_publickey", 0) != std::string::npos ||
        commands[1].find("_privatekey", 0) != std::string::npos ||
        (commands[1].find("..", 0) != std::string::npos)
    ) {
        throw command::CommandException("Forbidden");
    }

    if (strlen(contents.c_str()) > 300) {
        throw command::CommandException("Max file content allowed is 300 characters");
    }

    std::string physicalFilename = auth::hash(filename);
    metadata::write(physicalFilename, filename);
    std::string savePath = "filesystem/" + currentUser.usernameHashed + "/" + physicalPath + physicalFilename;

    char *contentsCopy = new char[contents.length() + 1];
    strcpy(contentsCopy, contents.c_str());

    if (currentUser.encryptSave(contentsCopy, savePath) == -1) {
        throw command::CommandException("An error occurred during encryption");
    }

    // check for expected shared file and update it
    std::string expectedSuffix = "/" + auth::hash("shared") + "/" + currentUser.usernameHashed + "/" + physicalFilename;

    for (const auto &entry : std::filesystem::directory_iterator("./filesystem")) {
        std::string entryPath = entry.path();
        std::string sharedUserName = metadata::get(entryPath.substr(13));
        entryPath += expectedSuffix;
        // if file exists for user, then we create it
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
char *_get_raw_content(std::string path)
{
    char *fileContent;

    std::ifstream ifs;
    ifs.open(path);

    if (!(ifs && ifs.is_open())) {
        throw command::CommandException("File does not exists");
        return fileContent;
    }
    ifs.seekg(0, std::ios::end);
    size_t fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    fileContent = new char[fileSize];
    ifs.read(fileContent, fileSize);
    ifs.close();

    return fileContent;
}

void command::sharefile(auth::User &currentUser, std::vector<std::string>& dir, std::string command)
{
    // check who is the username
    if (currentUser.isAdmin) {
        throw command::CommandException("Forbidden");
    }

    // group 1 must always be 'share', group 4 if using quotes or group 6 without quotes, group 7 is the user
    // regex rgx("^([A-Za-z0-9]+)\\s+((\"|')?([A-Za-z0-9\\s.]+)(\\3)|([A-Za-z0-9.]+))\\s+([a-z0-9]+)");
    std::regex rgx("^share\\s+((\"|')?([A-Za-z0-9\\-_\\s.]+)(\\3)|([A-Za-z0-9\\-_.]+))\\s+([a-z0-9_]+)");
    
    std::smatch matches;

    std::string filename, targetUsername, matchStr;
    if (regex_search(command, matches, rgx)) {
        for (size_t i = 0; i < matches.size(); ++i) {
            matchStr = matches[i].str();
            if ((i == 3 || i == 5) && matchStr.length() > 0) {
                filename = matchStr;
            }
            if (i == 6) {
                targetUsername = matchStr;
            }
        }
    } else {
        throw command::CommandException("Invalid share command. You should use command:\nshare <filename> <username>");
    }

    // check file exists by reading it
    std::string hashed_pwd;
    for (int i = 0; i < dir.size(); i++) {
        std::string hashed_dir = auth::hash(dir[i]);
        hashed_pwd += "/" + hashed_dir;
    }

    std::string hashed_filename = auth::hash(filename);
    std::string filepath = "./filesystem/" + currentUser.usernameHashed + hashed_pwd + "/" + hashed_filename;

    struct stat s;
    if (
        (stat(filepath.c_str(), &s)) == 0 &&
        (s.st_mode & S_IFDIR)
    ) {
        throw command::CommandException("Cannot share a directory, please enter a file name");
    }

    char *rawContent = _get_raw_content(filepath);

    // check that the user cannot share to themselves
    if (targetUsername == currentUser.username) {
        throw command::CommandException("You cannot share files to yourself.");
    }

    auth::User targetUser;
    targetUser.set_user(targetUsername);
    
    std::string private_key_path = "./filesystem/" + currentUser.usernameHashed + "/" + auth::hash(currentUser.keyName + "_privatekey");
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
        decryptedContent = currentUser.decrypt(rawContent);
    } catch (auth::AuthException a) {
        throw command::CommandException("An error occured while attempting to share file");
    }

    // Create directory if it doesn't exist
    std::string targetDirectory = "./filesystem/" + targetUser.usernameHashed + "/" + auth::hash("shared") + "/" + currentUser.usernameHashed;
    if (!std::filesystem::is_directory(std::filesystem::status(targetDirectory))) {
        if (mkdir(&targetDirectory[0], AUTH_DIR_PERMISSION) != 0) {
            throw command::CommandException("An error occurred during file share");
        }
    }

    // now encrypt and save new file
    std::string targetPath = targetDirectory + "/" + hashed_filename;
    if (targetUser.encryptSave(decryptedContent, targetPath) == -1) {
        throw command::CommandException("An error occurred during file share");
    }
    
    delete[] decryptedContent;

    std::cout << "File has been successfully shared" << std::endl;
}

std::string command::cat(auth::User &currentUser, const std::string& filename, std::vector<std::string> &dir,  const std::vector<std::string> &commands)
{
    if (commands.size() < 2) {
        throw command::CommandException("Please provide filename");
    }

    // TODO: filename can cause seg fault when empty
    std::string hashed_filename = auth::hash(filename);
    std::string full_path;

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
        (commands[1].find("_publickey", 0) != std::string::npos) ||
        (commands[1].find("_privatekey", 0) != std::string::npos) ||
        (commands[1].find("..", 0) != std::string::npos)
    ) {
        throw command::CommandException("Forbidden");
    }
    
    std::string catUsername = currentUser.username;
    if (currentUser.isAdmin) {
        catUsername = dir[0];
    }
    
    if (currentUser.isAdmin) {
        full_path = "filesystem/" + physicalPath + hashed_filename;
    } else {
        full_path = "filesystem/" + auth::hash(catUsername) + "/" + physicalPath + hashed_filename;
    }

    struct stat s;
    if (
        (stat(full_path.c_str(), &s) == 0) &&
        (s.st_mode & S_IFDIR)
    ) {
        throw command::CommandException("Cannot open a directory, please enter a file name");
    }

    std::ifstream infile(full_path);

    if (!(infile && infile.is_open())) {
        throw command::CommandException("Unable to open the file, please check file name");
    }

    infile.seekg(0, std::ios::end);
    size_t length = infile.tellg();
    infile.seekg(0, std::ios::beg);

    std::string public_key_path = "./publickeys/" + auth::hash(catUsername + "_publickey");
    RSA *public_key = auth::get_key(AUTH_KEY_TYPE_PUBLIC, public_key_path);

    if (public_key == NULL) {
        throw command::CommandException("Error! Public key not found or invalid");
    }

    char *contents = (char *)malloc(RSA_size(public_key));;
    infile.read(contents, length);
    infile.close();

    char *decrypt;

    std::string private_key_path;
    RSA *private_key;
    if (currentUser.isAdmin) {
        private_key_path = "./privatekeys/" + auth::hash(catUsername);
    } else {
        private_key_path = "./filesystem/" + auth::hash(catUsername) + "/" + auth::hash(currentUser.keyName + "_privatekey");
    }
    private_key = auth::get_key(AUTH_KEY_TYPE_PRIVATE, private_key_path);

    decrypt = (char *)malloc(RSA_size(public_key));

    if (private_key == NULL) {
        throw command::CommandException("Error! Private key not found or invalid");
    }

    int decrypt_length = auth::decrypt(RSA_size(private_key), (unsigned char *)contents, (unsigned char *)decrypt, private_key);
    if (decrypt_length == -1) {
        throw command::CommandException("An error occurred during decryption");
    }

    std::string output = decrypt;
    free(decrypt);
    return output;
}