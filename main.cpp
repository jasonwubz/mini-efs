#include <auth.h>
#include <command.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include <string.h>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <regex>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <openssl/sha.h>
#include <sys/types.h>
#include <jsoncpp/json/json.h>


using namespace std;

// Write encrypted content into a file stored locally
void create_encrypted_file(string filename, char* encrypted_content, RSA* key_pair) {
    // filename += ".bin";
    FILE* encrypted_file = fopen(&filename[0], "wb");
    if (encrypted_file == nullptr)
    {
        cout << "Unable to create file, please check directory permissions" << endl;
        return;
    }
    fwrite(encrypted_content, sizeof(*encrypted_content), RSA_size(key_pair), encrypted_file);
    fclose(encrypted_file);
}

int initial_folder_setup(){
    //create "filesystem", "privatekeys","publickeys" folders
    int status1 = mkdir("filesystem", 0777);
    int status2 = mkdir("privatekeys", 0777);
    int status3 = mkdir("publickeys", 0777);

    if (status1 == 0 && status2 == 0 && status3 == 0){
        cout << "Filesystem created successfully" << endl << endl;
    } else {
        cerr << "Failed to create filesystem. Please check permission and try again " << endl;
        return 1;
    }

    // Create an empty json file metadata.json
    Json::Value metadata;
    ofstream ofs("./metadata.json");
    Json::StreamWriterBuilder writerBuilder;
    unique_ptr<Json::StreamWriter> writer(writerBuilder.newStreamWriter());
    writer->write(metadata, &ofs);

    return 0;
}

void initial_adminkey_setup() {
    string username = "Admin";

    string random_byte_hex = auth::csprng();
    if (random_byte_hex.length() == 0) {
        return;
    }
    string key_name = username + "_" + random_byte_hex;

    auth::create_RSA(key_name);
    cout << "Admin Public/Private key pair has been created." << endl;
    cout << "Your private key_name is " << key_name << endl;
    cout << "Please store your key_name safely. Admin can login by command: " << endl;
    cout << "./fileserver " << key_name << endl << endl;
}

vector<string> split_string(const std::string& ipstr, const std::string& delimiter)
{
    size_t pos;
    std::string token;
    std::string ipstrcpy = ipstr;
    vector<string> splits;
    while ((pos = ipstrcpy.find(delimiter)) != std::string::npos) {
        token = ipstrcpy.substr(0, pos);
        splits.push_back(token);
        ipstrcpy.erase(0, pos + delimiter.length());
    }
    splits.push_back(ipstrcpy);
    return splits;
}

bool check_invalid_username(string username) {
    for(int i=0;i<username.length();i++){
        if(!std::isalpha(username[i]) && !std::isdigit(username[i])) {return false;}
    }
    return true;
}

void command_pwd(vector<string>& dir)
{
    if (dir.empty()) {
        cout << "/";
    }
    else {
        for (string str:dir) {
            cout << "/" << str;
        }
    }
    cout << endl;
    return;
}

void command_mkfile(const std::string& username, const std::string& filename, const std::string& curr_dir, const std::string& contents)
{
    string hashed_filename = auth::hash(filename);
    auth::write_to_metadata(hashed_filename, filename);
    std::string full_path = "filesystem/" + auth::hash(username) + "/" + curr_dir + hashed_filename;

    char *message = new char[contents.length() + 1];
    strcpy(message, contents.c_str());

    char *encrypt;

    string public_key_path = "./publickeys/" + auth::hash(username + "_publickey");
    RSA *public_key = auth::read_RSAkey("public", public_key_path);

    if (public_key == NULL)
    {
        cout << "Error! Public key not found or invalid" << endl;
        return;
    }

    encrypt = (char*)malloc(RSA_size(public_key));
    int encrypt_length = auth::public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_OAEP_PADDING);
    if(encrypt_length == -1) {
        cout << "An error occurred in public_encrypt() method" << endl;
        return;
    }

    create_encrypted_file(full_path, encrypt, public_key);

    // check for expected shared file and update it
    string expected_path_suffix = "/" + auth::hash("shared") + "/" + auth::hash(username) + "/" + hashed_filename;
    for (const auto & entry : filesystem::directory_iterator("./filesystem")) {
        string full_path = entry.path();
        string shared_user = auth::hash_to_val(full_path.substr(13));
        full_path += expected_path_suffix;
        // cout << full_path << endl;
        if (filesystem::exists(full_path)) {
            RSA *target_public_key;
            target_public_key = auth::read_RSAkey("public", "./publickeys/" + auth::hash(shared_user + "_publickey"));
            if (target_public_key == NULL) {
                // for some reason, the target's public key is lost so we cannot update it
                continue;
            }

            char *share_encrypted_content = (char*)malloc(RSA_size(target_public_key));
            int share_encrypt_length = auth::public_encrypt(contents.length() + 1, (unsigned char*)contents.c_str(), (unsigned char*)share_encrypted_content, target_public_key, RSA_PKCS1_OAEP_PADDING);
            if (share_encrypt_length == -1) {
                // failed to encrypt
                continue;
            }
            create_encrypted_file(full_path, share_encrypted_content, target_public_key);
            free(share_encrypted_content);
        }
    }
    free(encrypt);
    delete[] message;
}

std::string command_cat(const std::string& username, const std::string& filename, const std::string& curr_dir, const std::string& key_name)
{
    string hashed_filename = auth::hash(filename);
    std::string full_path = "filesystem/" + auth::hash(username) + "/" + curr_dir + hashed_filename;

    struct stat s;
    if(stat(full_path.c_str(), &s) == 0)
    {
        if(s.st_mode & S_IFDIR)
        {
            cout << "Cannot open a directory, please enter a file name" << endl;
            return "";
        }
    }

    std::ifstream infile(full_path);

    if (!(infile && infile.is_open())) {
        cout << "Unable to open the file, please check file name" << endl;
        return "";
    }

    infile.seekg(0, std::ios::end);
    size_t length = infile.tellg();
    infile.seekg(0, std::ios::beg);

    string public_key_path = "./publickeys/" + auth::hash(username + "_publickey");
    RSA *public_key = auth::read_RSAkey("public", public_key_path);

    if (public_key == NULL)
    {
        cout << "Error! Public key not found or invalid" << endl;
        return "";
    }

    char *contentss = (char*)malloc(RSA_size(public_key));;
    infile.read(contentss, length);
    infile.close();

    char *decrypt;

    std::string private_key_path;
    RSA *private_key;
    private_key_path = "./filesystem/" + auth::hash(username) + "/" + auth::hash(key_name + "_privatekey");
    private_key = auth::read_RSAkey("private", private_key_path);

    decrypt = (char*)malloc(RSA_size(public_key));

    if (private_key == NULL)
    {
        cout << "Error! Private key not found or invalid" << endl;
        return "";
    }

    int decrypt_length = auth::private_decrypt(RSA_size(private_key), (unsigned char*)contentss, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);
    if(decrypt_length == -1) {
        cout << "An error occurred in private_decrypt() method" << endl;
    }

    std::string output = decrypt;
    free(decrypt);
    return output;
}

std::string command_cat_admin(const std::string& username, const std::string& filename, const std::string& curr_dir, const std::string& key_name)
{
    string hashed_filename = auth::hash(filename);
    std::string full_path = "filesystem/" + curr_dir + hashed_filename;

    struct stat s;
    if(stat(full_path.c_str(), &s) == 0 )
    {
        if( s.st_mode & S_IFDIR )
        {
            cout << "Cannot open a directory, please enter a file name" << endl;
            return "";
        }
    }

    std::ifstream infile(full_path);

    if (!(infile && infile.is_open())) {
        cout << "Unable to open the file, please check file name" << endl;
        return "";
    }

    infile.seekg(0, std::ios::end);
    size_t length = infile.tellg();
    infile.seekg(0, std::ios::beg);

    string public_key_path = "./publickeys/" + auth::hash(username + "_publickey");
    RSA *public_key = auth::read_RSAkey("public", public_key_path);

    if (public_key == NULL)
    {
        cout << "Error! Public key not found or invalid" << endl;
        return "";
    }

    char *contentss = (char*)malloc(RSA_size(public_key));;
    infile.read(contentss, length);
    infile.close();

    char *decrypt;

    std::string private_key_path;
    RSA *private_key;
    private_key_path = "./privatekeys/" + auth::hash(username);

    private_key = auth::read_RSAkey("private", private_key_path);

    decrypt = (char*)malloc(RSA_size(public_key));

    if (private_key == NULL)
    {
        cout << "Error! Private key not found or invalid" << endl;
        return "";
    }

    int decrypt_length = auth::private_decrypt(RSA_size(private_key), (unsigned char*)contentss, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);
    if(decrypt_length == -1) {
        cout << "An error occurred in private_decrypt() method" << endl;
    }

    return decrypt;
}

void command_cd(vector<string>& dir, string change_dir, string username) {
    stringstream test(change_dir);
    string segment;
    vector<string> seglist;
    vector<string> new_dir;

    // split input by '/'
    while(getline(test, segment, '/'))
    {
        seglist.push_back(segment);
    }
    
    // if the input started by "." or "..", use the current directory for prefix
    if (seglist[0] == "." || seglist[0] == ".." || !seglist[0].empty()) {
        new_dir = dir;
    }
    
    // build new directory
    for (string seg : seglist) {
        if (seg == "." || seg.empty()) {
            continue;
        }
        else if (seg == "..") {
            if (new_dir.empty()) {
                cout << "Invalid directory!" << endl;
                return;
            }
            new_dir.pop_back();
        }
        else {
            new_dir.push_back(seg);
        }
    }

    // convert new directory to string in order to use std::filesystem functions
    string check_dir = std::filesystem::current_path().string() + "/" + "filesystem";
    if (username != "Admin") {
        check_dir = check_dir + "/" + auth::hash(username);
    }
    for (string str : new_dir) {
        if (!str.empty()) {
            check_dir = check_dir + "/" + auth::hash(str);
        }
    }
    // cout << "TEST: " << check_dir << endl;
    if (std::filesystem::is_directory(std::filesystem::status(check_dir)) ) {
        dir = new_dir;
        cout << "Change directory to: ";
        command_pwd(dir); 
    }
    else {
        cout << "Invalid directory!" << endl;
    }

    return;
}

bool is_admin(string username) {
    if (strcasecmp(username.c_str(), "admin") == 0) {
        return true;
    }
    return false;
}

void command_sharefile(string username, string key_name, vector<string>& dir, string user_command) {
    // check who is the username
    if (is_admin(username) == true) {
        cout << "Forbidden" << endl;
        return;
    }

    // group 1 must always be 'share', group 4 if using quotes or group 6 without quotes, group 7 is the user
    // regex rgx("^([A-Za-z0-9]+)\\s+((\"|')?([A-Za-z0-9\\s.]+)(\\3)|([A-Za-z0-9.]+))\\s+([a-z0-9]+)");
    regex rgx("^share\\s+((\"|')?([A-Za-z0-9\\-_\\s.]+)(\\3)|([A-Za-z0-9\\-_.]+))\\s+([a-z0-9_]+)");
    
    smatch matches;

    string filename, target_username, match_string;
    if (regex_search(user_command, matches, rgx)) {
        for (size_t i = 0; i < matches.size(); ++i) {
            match_string = matches[i].str();
            if ((i == 3 || i == 5) && match_string.length() > 0) {
                filename = match_string;
            }
            if (i == 6) {
                target_username = match_string;
            }
        }
    } else {
        cout << "Invalid share command. You should use command: " << endl;
        cout << "share <filename> <username>" << endl;
        return;
    }

    // check file exists by reading it
    string hashed_pwd;
    for (int i = 0; i < dir.size(); i++) {
        string hashed_dir = auth::hash(dir[i]);
        hashed_pwd += "/" + hashed_dir;
    }

    string hashed_username = auth::hash(username);
    string hashed_filename = auth::hash(filename);
    string filepath = "./filesystem/" + hashed_username + hashed_pwd + "/" + hashed_filename;

    struct stat s;
    if(stat(filepath.c_str(), &s) == 0)
    {
        if(s.st_mode & S_IFDIR)
        {
            cout << "Cannot share a directory, please enter a file name" << endl;
            return;
        }
    }

    ifstream ifs;
    ifs.open(filepath);
    if (!(ifs && ifs.is_open())) {
        cout << "Filename '" << filename << "' does not exist." << endl;
        return;
    }
    ifs.seekg(0, ios::end);
    size_t full_size = ifs.tellg();
    // rewind to allow reading
    ifs.seekg(0, ios::beg);

    // create file content buffer
    char* file_content = new char[full_size];
    ifs.read(file_content, full_size);
    ifs.close();

    // check that the user cannot share to themselves
    if (target_username == username) {
        cout << "You cannot share files to yourself." << endl;
        return;
    }
    
    RSA *private_key;
    string private_key_path = "./filesystem/" + hashed_username + "/" + auth::hash(key_name + "_privatekey");
    private_key = auth::read_RSAkey("private", private_key_path);
    if (private_key == NULL) {
        cout << "Error! Private key not found or invalid" << endl;
        return;
    }
    if (private_key_path == filepath) {
        cout << "You cannot share your private key." << endl;
        return;
    }

    // check that target username exists (a valid user have a public key)
    RSA *target_public_key;
    string hashed_target_username = auth::hash(target_username);
    target_public_key = auth::read_RSAkey("public", "./publickeys/" + auth::hash(target_username + "_publickey"));
    if (target_public_key == NULL) {
        cout << "Error! Public key not found or invalid" << endl;
        return;
    }
    if (target_public_key == NULL){
        cout << "User '" << target_username << "' does not exists." << endl;
        return;
    }

    // decrypt file for copying
    char *decrypted_file_content = new char[full_size];
    int decrypt_length = auth::private_decrypt(full_size, (unsigned char*)file_content, (unsigned char*)decrypted_file_content, private_key, RSA_PKCS1_OAEP_PADDING);
    if (decrypt_length == -1) {
        cout << "An error occurred during file share" << endl;
        return;
    }

    // encrypt shared file with target's public key
    char *share_encrypted_content = (char*)malloc(RSA_size(target_public_key));
    int share_encrypt_length = auth::public_encrypt(strlen(decrypted_file_content) + 1, (unsigned char*)decrypted_file_content, (unsigned char*)share_encrypted_content, target_public_key, RSA_PKCS1_OAEP_PADDING);
    if (share_encrypt_length == -1) {
        cout << "An error occurred during file share" << endl;
        return;
    }

    // directory exists?
    string target_share_directory = "./filesystem/" + hashed_target_username + "/" + auth::hash("shared") +"/" + hashed_username;
    // cout << "Target directory:" << target_share_directory << endl;
    if (!std::filesystem::is_directory(std::filesystem::status(target_share_directory))) {
        int dir_create_status = mkdir(&target_share_directory[0], 0777);
        if (dir_create_status != 0) {
            cout << "An error occurred during file share" << endl;
            return;
        }
    }

    // now write new file
    string target_filepath = target_share_directory + "/" + hashed_filename;
    create_encrypted_file(target_filepath, share_encrypted_content, target_public_key);
    cout << "File '" << filename << "' has been successfully shared with user '" << target_username << "'" << endl;
}

void command_mkdir(vector<string>& dir, string new_dir, string username) {
    string cur_dir;
    for (string str:dir) {
        cur_dir = cur_dir + '/' + auth::hash(str);
    }

    if (new_dir.find(".") != -1 or new_dir.find("..") != -1 or new_dir.find("/") != -1){
        cout << "Invalid directory name." << endl;
        return;
    }

    if(username != "Admin"){
        if (!dir.empty()){
            if (cur_dir.substr(1,65) == auth::hash("shared"))
            {
                cout << "Forbidden: Cannot create directory in /shared" << endl;
            }
            else{
                auth::write_to_metadata(auth::hash(new_dir),new_dir);
                new_dir = std::filesystem::current_path().string() + "/filesystem/" + auth::hash(username) + '/' + cur_dir.substr(1) + '/' + auth::hash(new_dir);

                char* dirname = strdup(new_dir.c_str());
                if (mkdir(dirname, 0777) == -1)
                    cerr << "Error: directory exists."<< endl;
                else
                    cout << "Directory created" << endl;
                free(dirname);
            }           
        }
        else{
            cout << "Forbidden" << endl;
        }
    }
    else{
        cout << "Invalid command for admin!" << endl;
    }
}

bool isWhitespace(std::string s){
    for(int index = 0; index < s.length(); index++){
        if(!std::isspace(s[index]))
            return false;
    }
    return true;
}

int main(int argc, char** argv) {

    string username, user_command, key_name;

    if (argc != 2) {
        cout << "Wrong command to start the fileserver. You should use command: " << endl;
        cout << "./fileserver key_name" << endl;
        return 1;
    }

    cout << "--------------------------------------------------------" << endl;
    cout << "     You are accessing Encrypted Secure File System     " << endl;
    cout << "--------------------------------------------------------" << endl << endl;

    struct stat st, st1, st2;
    if (stat("filesystem", &st) == -1 && stat("privatekeys", &st1) == -1 && stat("publickeys", &st2) == -1)
    {
        //Initial Setup
        cout << "No file system exists yet. Execute Initial setup..." << endl << endl;

        int folder_result = initial_folder_setup();
        if (folder_result == 1) {return 1;}

        //Generate random salt value using cryptographically secure random function
        string random_salt = auth::csprng();
        auth::write_to_metadata("salt", random_salt);

        auth::write_to_metadata(auth::hash("personal"), "personal");
        auth::write_to_metadata(auth::hash("shared"), "shared");

        initial_adminkey_setup();

        cout << "Initial setup finshed, Fileserver closed. Admin now can login using the admin keyfile" << endl;
        return 0;

    } else if (stat("filesystem", &st) == -1 || stat("privatekeys", &st1) == -1 || stat("publickeys", &st2) == -1){
            cout << "Partial file system exist. Please remove folder filesystem/privatekeys/publickeys and try again." << endl;
            return 1;
    } else {
        // cout << "Directory already exists" << endl;
        // Time to do user authentication

        key_name = argv[1];
        int login_result = auth::login_authentication(key_name);
        if (login_result == 1){
            cout << "Invalid key_name is provided. Fileserver closed." << endl;
            return 1;
        } else {
            size_t pos = key_name.find("_");
            username = key_name.substr(0,pos);
            cout << "Welcome! Logged in as " << username << endl;
            command::show_help(is_admin(username));
        }
    }

    /* ....Implement fileserver different commands...... */
    vector<string> dir;
    
    while (true){
        cout << endl;
        cout << "> ";
        getline(cin,user_command);
        // cout << "User input: " << user_command << endl;
        vector<string> splits = split_string(user_command, " ");

        if (user_command == "exit") {
            cout << "Fileserver closed. Goodbye " << username << " :)" << endl;
            return 0;
        }

        /* Directory commands */
        // 1. pwd 
        //
        else if (user_command == "pwd") {
            command_pwd(dir);
        }

        // 2. cd  
        //
        else if (user_command.substr(0, 2) == "cd" && user_command.substr(2, 1) == " ") {
            command_cd(dir, user_command.substr(3), username);
        }
        // 3. ls  
        //
        else if (user_command == "ls") {
            command::ls(dir, username);
        }

        // 4. mkdir  
        //
        else if (user_command.substr(0,5) == "mkdir" && user_command.substr(5,1) == " " && !isWhitespace(user_command.substr(6)) ) {
            command_mkdir(dir, user_command.substr(6), username);
        }

        /* File commands section*/

        // 6. share 
        //
        else if (user_command.rfind("share", 0) == 0) {
            command_sharefile(username, key_name, dir, user_command);
        }
        // 5. cat
        else if (splits[0] == "cat")
        {
            if (splits.size() < 2)
            {
                cout << "Please provide filename" << endl;
                continue;
            }

            std::string curr_dir;
            std::string curr_dir_hashed;
            for (const string& str:dir) {
                curr_dir.append(str);
                curr_dir_hashed.append(auth::hash(str));
                curr_dir.append("/");
                curr_dir_hashed.append("/");
            }

            if (curr_dir.empty())
            {
                cout << "Forbidden" << endl;
                continue;
            }

            if (splits[1].find("_publickey", 0) != std::string::npos || splits[1].find("_privatekey", 0) != std::string::npos || (splits[1].find("..", 0) != std::string::npos))
            {
                std::cout << "Forbidden" << endl;
                continue;
            }

            if (username == "Admin")
            {
                std::string contents = command_cat_admin(dir[0], splits[1], curr_dir_hashed, key_name);
                std::cout << contents << endl;
            }
            else
            {
                std::string contents = command_cat(username, splits[1], curr_dir_hashed, key_name);
                std::cout << contents << endl;
            }
        }

        // 6. share
        // else if (user_command ....) {

        // }

        // 7. mkfile
        else if (splits[0] == "mkfile")
        {
            if (splits.size() < 3 || splits[2].empty())
            {
                cout << "Filename and file contents cannot be empty" << endl;
                continue;
            }

            std::string curr_dir;
            std::string curr_dir_hashed;
            for (const string& str:dir) {
                curr_dir.append(str);
                curr_dir_hashed.append(auth::hash(str));
                curr_dir.append("/");
                curr_dir_hashed.append("/");
            }

            if (username == "Admin")
            {
                cout << "Sorry, admin cannot create files" << endl;
                continue;
            }

            if (curr_dir.empty() || curr_dir.rfind("shared", 0) == 0)
            {
                cout << "Forbidden" << endl;
                continue;
            }

            if (splits[1].find("_publickey", 0) != std::string::npos || splits[1].find("_privatekey", 0) != std::string::npos || (splits[1].find("..", 0) != std::string::npos))
            {
                std::cout << "Forbidden" << endl;
                continue;
            }

            size_t pos = user_command.find(" ", user_command.find(" ") + 1);
            string file_contents = user_command.substr(pos + 1);

            if (strlen(file_contents.c_str()) > 300)
            {
                cout << "Max file content allowed is 300 characters" << endl;
                continue;
            }

            command_mkfile(username, splits[1], curr_dir_hashed, file_contents);
        }

        /* Admin specific feature */
        // 8. adduser <username>
        // check if user_command start with adduser
        else if (user_command.rfind("adduser", 0) == 0) {
            if (username != "Admin"){
                cout << "Forbidden. Only Admin can perform adduser command." << endl;
                continue; 
            }
            size_t pos = user_command.find(" ");
            if (pos == -1) {
                // to counter malicious input: adduser
                cout << "No new username provided." << endl;
                continue;
            }
            string new_username = user_command.substr(pos+1, -1);
            if (new_username == ""){
                // to counter malicious input: adduser 
                cout << "No new username provided." << endl;
                continue;
            }
            if (new_username.length() > 10){
                cout << "Invalid new username. Maximum 10 characters." << endl;
                continue;
            }
            if (strcasecmp(new_username.c_str(),"admin") == 0){
                cout << "Invalid new username: " << new_username << endl;
                continue;
            }
            if (!check_invalid_username(new_username)){
                cout << "Invalid new username. Only alphabets and numbers are allowed in a username." << endl;
                continue;
            }
            struct stat st;
            string root_folder_path = "filesystem/" + auth::hash(new_username);
            if (stat(&root_folder_path[0], &st) != -1){
                cout << "User " << new_username << " already exists" << endl;
                continue;
            }
            //passed all exception checks, now we create new user
            command::adduser(new_username);
        } else {
            cout << "Invalid command." << endl;
        }

    }

    
}

