# Mini-EFS
This is a fork of an academic group project. My fork is simply a refactoring exercise. Some new features may be added in the future.

## Overview
The Mini-EFS (Mini Encrypted File System) is a locally operated program that securely save messages as encrypted files that can then be shared with other users in the same local  environment.

When you first run the program, it will create the necessary folders and an admin user. All secret keys (`key_name`) are generated randomly.

Here is a list of commands:
- `cd <directory>` - Change directory
- `pwd` - Print the current directory
- `ls` - List the files and directories in the current directory
- `cat` - Print content of the given filename
- `exit` - Terminate the program
- `help` - This list of commands
- `share <filename> <username>` (for regular user only) - Share the file `<filename>` with the target user `<username>`
- `mkfile <filename> <contents>` (for regular user only) - Create a new file `<filename>` with the ascii printable contents `<contents>`
- `adduser <username>` (for admin only) - Add new user by given username

## Prerequisites

Except for openssl, please also make sure jsoncpp is installed before you compile the code
```bash
sudo apt install libjsoncpp-dev
```

## Setup
Compile and prepare the binary:

```bash
cd /your-path-to/mini-efs

# compile headers
g++ -c -I. src/auth.cpp src/command.cpp src/metadata.cpp

# compile main program as fileserver
g++ -I. auth.o command.o metadata.o main.cpp -o fileserver -lcrypto -ljsoncpp

# give execute permission binary
chmod +x fileserver
```

Run the `fileserver` binary:

```bash
./fileserver key_name
```