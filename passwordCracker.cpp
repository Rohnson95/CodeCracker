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

std::string sha256(const std::string &input)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    // Convert the binary hash to a hex string
    std::string hashedPassword;
    for (unsigned int i = 0; i < hash_len; ++i)
    {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        hashedPassword += hex;
    }

    return hashedPassword;
}

bool compareByHash(const PasswordHashPair &a, const PasswordHashPair &b)
{
    return a.hash < b.hash;
}

int hashPasswords()
{
    std::fstream passwordFile("commonPasswords.txt", std::ios::in | std::ios::out);
    if (!passwordFile.is_open())
    {
        std::cout << "Error opening file" << std::endl;
        return 1;
    }
    std::vector<PasswordHashPair> passwordHashPairs;
    std::string password;
    while (getline(passwordFile, password))
    {
        std::istringstream iss(password);
        std::string hashedPassword = sha256(password);
        passwordFile << ":" << hashedPassword << std::endl;
    }

    passwordFile.close();
}