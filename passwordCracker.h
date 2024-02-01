#ifndef PASSWORDCRACKER_H
#define PASSWORDCRACKER_H
#include <iostream>
#include <vector>
#include <string>
#include <regex>
#include <fstream>
#include <conio.h>
#include <limits>
#include <openssl/evp.h>
#include <openssl/rand.h>

struct PasswordHashPair
{
    std::string password;
    std::string hash;
};

std::string sha256(const std::string &input);

bool compareByHash(const PasswordHashPair &a, const PasswordHashPair &b);

int hashPasswords();

int mainCracker();

#endif // !PASSWORDCRACKER_H