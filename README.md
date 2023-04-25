# mini-efs
This is a fork of an academic group project. My fork is simply a refactoring exercise. Some new features may be added in the future.

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
g++ -c -I. auth.cpp command.cpp metadata.cpp

# compile main program as fileserver
g++ -I. auth.o command.o metadata.o main.cpp -o fileserver -lcrypto -ljsoncpp

# give execute permission binary
chmod +x fileserver
```

Run the `fileserver` binary:

```bash
./fileserver key_name
```