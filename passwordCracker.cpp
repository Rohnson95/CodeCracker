#include <iostream>
#include <vector>
#include <string>
#include <regex>
#include <fstream>
#include <conio.h>
#include <limits>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "passwordCracker.h"
// struct PasswordHashPair
// {
//     std::string password;
//     std::string hash;
// };

// std::string sha256(const std::string &input)
// {
//     EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
//     const EVP_MD *md = EVP_sha256();
//     unsigned char hash[EVP_MAX_MD_SIZE];
//     unsigned int hash_len;

//     EVP_DigestInit_ex(mdctx, md, nullptr);
//     EVP_DigestUpdate(mdctx, input.c_str(), input.length());
//     EVP_DigestFinal_ex(mdctx, hash, &hash_len);
//     EVP_MD_CTX_free(mdctx);

//     // Convert the binary hash to a hex string
//     std::string hashedPassword;
//     for (unsigned int i = 0; i < hash_len; ++i)
//     {
//         char hex[3];
//         sprintf(hex, "%02x", hash[i]);
//         hashedPassword += hex;
//     }

//     return hashedPassword;
// }

bool compareByHash(const PasswordHashPair &a, const PasswordHashPair &b)
{
    return a.hash < b.hash;
}

int hashPasswords()
{
    // std::ifstream passwordFile("commonPasswords.txt");
    // if (!passwordFile.is_open())
    // {
    //     std::cout << "Failed to open password file" << std::endl;
    //     return 1;
    // }
    // std::vector<PasswordHashPair> passwordHashPairs;
    // std::string password;

    // while (getline(passwordFile, password))
    // {
    //     std::string hashedPassword = sha256(password);

    //     PasswordHashPair pair = {password, hashedPassword};
    //     passwordHashPairs.push_back(pair);
    // }

    // std::sort(passwordHashPairs.begin(), passwordHashPairs.end(), compareByHash);
    // passwordFile.close();

    // std::ofstream outputCommon("sorted_common_passwords.txt");

    // if (!outputCommon.is_open())
    // {
    //     std::cout << "Failed to open output file" << std::endl;
    //     return 1;
    // }
    // for (const auto &pair : passwordHashPairs)
    // {
    //     outputCommon << pair.password << ":" << pair.hash << std::endl;
    // }
    // outputCommon.close();

    // return 0;
}
// TODO: Make a brute force checker for the sorted_common_passwords.txt file to see if you can get the plaintext password from the hash
// This should be doable by taking a hash input from the user and checking against the file for a match, and then printing the plaintext password if there is a match

// create a function that converts a hash to a plaintext password
// create a function that takes a hash and checks it against the sorted_common_passwords.txt file
// if there is a match, print the plaintext password
// if there is no match, print "Password not found"

int mainCracker()
{
    std::ifstream passwordFile("sorted_common_passwords.txt");
    if (!passwordFile.is_open())
    {
        std::cout << "Failed to open password file" << std::endl;
        return 1;
    }
    std::vector<std::pair<std::string, std::string>> passwordHashPairs;
    std::string line;
    while (std::getline(passwordFile, line))
    {
        std::istringstream iss(line);
        std::string password, fileHash;
        std::getline(iss, password, ':');
        std::getline(iss, fileHash);
        passwordHashPairs.push_back({fileHash, password});
    }

    std::string inputHash;
    std::cout << "Enter a hash: ";
    std::cin >> inputHash;
    auto startTime = std::chrono::high_resolution_clock::now();
    auto it = std::lower_bound(passwordHashPairs.begin(), passwordHashPairs.end(), inputHash,
                               [](const std::pair<std::string, std::string> &pair, const std::string &hash)
                               {
                                   return pair.first < hash;
                               });

    if (it != passwordHashPairs.end() && it->first == inputHash)
    {
        std::cout << "Match found! Password is: " << it->second << std::endl;
    }
    else
    {
        std::cout << "Password not found" << std::endl;
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    std::cout << "took: " << std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count() << "microseconds" << std::endl;
    passwordFile.close();
    return 0;
}