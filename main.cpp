#include <iostream>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include <string.h>
#include <vector>
#include <algorithm>
#include <sstream>
#include <filesystem>


using namespace std;

// This function will create public/private key pairs under /publickeys folder and /privatekeys folder
// keyfile's naming convension: username_randomnumber_publickey and username_randomnumber_privatekey
// Example: Admin_2018509453_privatekey
void create_RSA(string key_name) {
    size_t pos = key_name.find("_");
    string username = key_name.substr(0,pos);

    if (username == "Admin") {

        string publickey_path = "./publickeys/" + username + "_publickey";
        string privatekey_path = key_name + "_privatekey";
        
        RSA   *rsa = NULL;
        FILE  *fp  = NULL;
        FILE  *fp1  = NULL;

        BIGNUM *bne = NULL;
        bne = BN_new();
        BN_set_word(bne, 59);

        RSA *keypair = NULL;
        keypair = RSA_new();
        //2048 bit key
        RSA_generate_key_ex(keypair, 2048, bne, NULL);

        //generate public key and store to local
        fp = fopen(&publickey_path[0], "w");
        PEM_write_RSAPublicKey(fp, keypair);
        fclose(fp);
        
        //generate private key and store to local
        fp1 = fopen(&privatekey_path[0], "w");
        PEM_write_RSAPrivateKey(fp1, keypair, NULL, NULL, 0, NULL, NULL);
        fclose(fp1);
    } else {
        // normal user's public key & private key file creation
        string publickey_path = "./publickeys/" + username + "_publickey";
        string privatekey_path = "filesystem/" + username + "/" + key_name + "_privatekey";
        string privatekey_foradmin_path = "./privatekeys/" + username ;
        
        RSA   *rsa = NULL;
        FILE  *fp  = NULL;
        FILE  *fp1  = NULL;
        FILE  *fp2  = NULL;

        BIGNUM *bne = NULL;
        bne = BN_new();
        BN_set_word(bne, 59);

        RSA *keypair = NULL;
        keypair = RSA_new();
        RSA_generate_key_ex(keypair, 2048, bne, NULL);

        //generate public key and store to local
        fp = fopen(&publickey_path[0], "w");
        PEM_write_RSAPublicKey(fp, keypair);
        fclose(fp);
        
        //generate private key and store to local
        fp1 = fopen(&privatekey_path[0], "w");
        PEM_write_RSAPrivateKey(fp1, keypair, NULL, NULL, 0, NULL, NULL);
        fclose(fp1);

        //Store a copy of private key in privatekeys for admin usage only
        fp2 = fopen(&privatekey_foradmin_path[0], "w");
        PEM_write_RSAPrivateKey(fp2, keypair, NULL, NULL, 0, NULL, NULL);
        fclose(fp2);
    }

}

// This function will read RSA (public or private) keys specified by key_path
RSA * read_RSAkey(string key_type, string key_path){
    
    FILE  *fp  = NULL;
    RSA   *rsa = NULL;

    fp = fopen(&key_path[0], "rb");
    if (fp == NULL){
        cout << "invalid key_name provided";
        return rsa;
    }

    if (key_type == "public"){
        PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
        fclose(fp);        
    } else if (key_type == "private"){
        PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
        fclose(fp);
    }
    return rsa;
}

// This function implement RSA public key encryption
int public_encrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {
    
    int result = RSA_public_encrypt(flen, from, to, key, padding);
    return result;
}

// This function implement RSA private key decryption
int private_decrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {

    int result = RSA_private_decrypt(flen, from, to, key, padding);
    return result;
}

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
            return 0;
        } else {
            cerr << "Failed to create filesystem. Please check permission and try again " << endl;
            return 1;
        }
}

void initial_adminkey_setup(){

    // Providing a seed value
	srand((unsigned) time(NULL));
	// Get a random number
	int random = rand() % 9999999999;

    string username = "Admin";
    string key_name = username + "_" + to_string(random);

    create_RSA(key_name);
    cout << "Admin Public/Private key pair has been created." << endl;
    cout << "Your private key_name is " << key_name << endl;
    cout << "Please store your key_name safely. Admin can login by command: " << endl;
    cout << "./fileserver " << key_name << endl << endl;
}

int login_authentication(string key_name){
    RSA *private_key;
    RSA *public_key;
    string public_key_path, private_key_path, username;

    size_t pos = key_name.find("_");
    username = key_name.substr(0,pos);
    
    public_key_path = "./publickeys/" + username + "_publickey";
    public_key = read_RSAkey("public", public_key_path);    

    if (username == "Admin"){
        private_key_path = key_name + "_privatekey";
    } else {
        private_key_path = "./filesystem/" + username + "/" + key_name + "_privatekey";
    }
    private_key = read_RSAkey("private", private_key_path);
    
    if (public_key == NULL || private_key == NULL){
        //not such key by searching the provided key_name
        // cout << "Invalid key_name is provided. Fileserver closed." << endl;
        return 1;
    } else {
        // Successfully read public key and private key. Now User authentication
        // We uses private key to decrypt a message that was encrypted with the corresponding public key.
        // If the decryption is successful, the user is authenticated and can proceed with the session.

        char message[] = "My secret";
        char *encrypt = NULL;
        char *decrypt = NULL;

        // Do RSA encryption using public key
        encrypt = (char*)malloc(RSA_size(public_key));
        int encrypt_length = public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_OAEP_PADDING);
        if(encrypt_length == -1) {
            // cout << "An error occurred in public_encrypt() method" << endl;
            return 1;
        }
        
        // Try to do RSA decryption using corresponding private key
        decrypt = (char *)malloc(encrypt_length);
        int decrypt_length = private_decrypt(encrypt_length, (unsigned char*)encrypt, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);
        if(decrypt_length == -1) {
            // cout << "An error occurred in private_decrypt() method" << endl;
            return 1;
        }
        if (strcmp(decrypt, message) == 0){
            // cout << "Successfully login" << endl;
            // cout << decrypt << endl;
            return 0;
        } else {
            return 1;
        }
    }
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

bool check_invalid_username(string username){
    for(int i=0;i<username.length();i++){
        if(!std::isalpha(username[i]) && !std::isdigit(username[i])) {return false;}
    }
    return true;
}

int user_folder_setup(string new_username){
    string root_folder_path = "filesystem/" + new_username;
    string personal_folder_path = root_folder_path + "/personal";
    string shared_folder_path = root_folder_path + "/shared";

    int status1 = mkdir(&root_folder_path[0], 0777);
    int status2 = mkdir(&personal_folder_path[0], 0777);
    int status3 = mkdir(&shared_folder_path[0], 0777);

    if (status1 == 0 && status2 == 0 && status3 == 0){
        cout << "User " << new_username << " folders created successfully" << endl << endl;
        return 0;
    } else {
        cerr << "Failed to create user folders. Please check permission and try again " << endl;
        return 1;
    }
}

void cmd_adduser(string new_username){
    // create user folders
    int result = user_folder_setup(new_username);
    if (result) {return;}

    // create users RSA public key and private keys (2 copies)
    // Providing a seed value
	srand((unsigned) time(NULL));
	// Get a random number
	int random = rand() % 9999999999;

    string key_name = new_username + "_" + to_string(random);
    create_RSA(key_name);
    cout << "User " << new_username << " Public/Private key pair has been created." << endl;
    cout << "The private key_name is " << key_name << endl;
    cout << "Please give this key_name to user and let user know that it must be remained secret to him/herself only." << endl;
    cout << "User " << new_username << " can login by command: " << endl;
    cout << "./fileserver " << key_name << endl << endl;

}


void command_pwd(vector<string>& dir) {
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
    std::string full_path = "filesystem/" + username + "/" + curr_dir + filename;

    char *message = new char[contents.length() + 1];
    strcpy(message, contents.c_str());

    char *encrypt;

    string public_key_path = "./publickeys/" + username + "_publickey";
    RSA *public_key = read_RSAkey("public", public_key_path);

    encrypt = (char*)malloc(RSA_size(public_key));
    int encrypt_length = public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_OAEP_PADDING);
    if(encrypt_length == -1) {
        cout << "An error occurred in public_encrypt() method" << endl;
        return;
    }

    create_encrypted_file(full_path, encrypt, public_key);
}


std::string command_cat(const std::string& username, const std::string& filename, const std::string& curr_dir, const std::string& key_name)
{
    std::string full_path = "filesystem/" + username + "/" + curr_dir + filename;
    std::ifstream infile(full_path);

    if (!(infile && infile.is_open())) {
        cout << "Unable to open the file, please check file name" << endl;
        return "";
    }

    infile.seekg(0, std::ios::end);
    size_t length = infile.tellg();
    infile.seekg(0, std::ios::beg);

    string public_key_path = "./publickeys/" + username + "_publickey";
    RSA *public_key = read_RSAkey("public", public_key_path);

    char *contentss = (char*)malloc(RSA_size(public_key));;
    infile.read(contentss, length);
    infile.close();

    char *decrypt;

    std::string private_key_path;
    RSA *private_key;
    private_key_path = "./filesystem/" + username + "/" + key_name + "_privatekey";

    private_key = read_RSAkey("private", private_key_path);

    decrypt = (char*)malloc(RSA_size(public_key));

    int decrypt_length = private_decrypt(RSA_size(private_key), (unsigned char*)contentss, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);
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
    string check_dir = filesystem::current_path().string() + "/" + "filesystem";
    if (username != "Admin") {
        check_dir = check_dir + "/" + username;
    }
    for (string str : new_dir) {
        if (!str.empty()) {
            check_dir = check_dir + "/" + str;
        }
    }
    // cout << "TEST: " << check_dir << endl;
    if ( filesystem::is_directory(filesystem::status(check_dir)) ) {
        dir = new_dir;
        cout << "Change directory to: ";
        command_pwd(dir); 
    }
    else {
        cout << "Invalid directory!" << endl;
    }

    return;
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
        int login_result = login_authentication(key_name);
        if (login_result == 1){
            cout << "Invalid key_name is provided. Fileserver closed." << endl;
            return 1;
        } else {
            size_t pos = key_name.find("_");
            username = key_name.substr(0,pos);
            cout << "Welcome! Logged in as " << username << endl;
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
        // else if (user_command ....) {

        // }

        // 4. mkdir  
        //
        // else if (user_command ....) {

        // }

        /* File commands section*/

        // 5. cat
        else if (splits[0] == "cat")
        {
            std::string curr_dir;
            for (const string& str:dir) {
                curr_dir.append(str);
                curr_dir.append("/");
            }

            std::string contents = command_cat(username, splits[1], curr_dir, key_name);
            std::cout << contents;
        }

        // 6. share
        // else if (user_command ....) {

        // }

        // 7. mkfile
        else if (splits[0] == "mkfile")
        {
            std::string curr_dir;
            for (const string& str:dir) {
                curr_dir.append(str);
                curr_dir.append("/");
            }

            if (username == "Admin")
            {
                cout << "Sorry, admin cannot create files" << endl;
                continue;
            }

            if (curr_dir.empty() || curr_dir == "shared/")
            {
                cout << "Forbidden";
                continue;
            }

            if (splits.size() < 3 || splits[2].empty())
            {
                cout << "File cannot be empty";
                continue;
            }

            command_mkfile(username, splits[1], curr_dir, splits[2]);
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
            string root_folder_path = "filesystem/" + new_username;
            if (stat(&root_folder_path[0], &st) != -1){
                cout << "User " << new_username << " already exists" << endl;
                continue;
            }
            //passed all exception checks, now we create new user
            cmd_adduser(new_username);
        }


        else {
            cout << "Invalid command." << endl;
        }

    }

    
}

