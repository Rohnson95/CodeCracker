#include <iostream>
#include <vector>
#include <string>
#include <regex>
#include <fstream>
#include <conio.h>
#include <limits>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "passwordCracker.h"
struct UserInfo
{
    std::string email;
    std::string password;
    // const std::string &email
    bool isValidEmail() const
    {
        const std::regex pattern("(\\w+)(\\.|_)?(\\w*)@(\\w+)(\\.(\\w+))+");

        return std::regex_match(email, pattern);
    }
    bool isValidPassword() const
    {
        const std::regex pattern("(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\",.<>?]).{8,}");
        return std::regex_match(password, pattern);
    }
};
std::string generateSalt()
{
    const int saltLength = 16;
    unsigned char buffer[saltLength];
    RAND_bytes(buffer, saltLength);

    std::string salt;
    for (int i = 0; i < saltLength; ++i)
    {
        salt += char('a' + (buffer[i] % 26));
    }

    return salt;
}
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
bool checkPassword(const std::string &inputPassword, const std::string &storedHash, const std::string &storedSalt)
{
    return sha256(inputPassword + storedSalt) == storedHash;
}
void writeToFile(const UserInfo &user)
{
    std::ofstream userFile("users.txt", std::ios::app);

    if (userFile.is_open())
    {
        userFile << user.email << ":" << sha256(user.password);
        userFile << "\n";
        userFile.close();
        std::cout << "User Information successfully added\n";
    }
    else
    {
        std::cerr << "Error Opening File\n";
    }
}
void writeToHashSaltFile(const UserInfo &user)
{
    std::ofstream hashSaltFile("users_with_salt.txt", std::ios::app);

    if (hashSaltFile.is_open())
    {
        std::string salt = generateSalt();
        std::string saltedPassword = user.password + salt;
        hashSaltFile << user.email << ":" << sha256(saltedPassword) << ":" << salt;
        hashSaltFile << "\n";
        hashSaltFile.close();
        std::cout << "User Information successfully added\n";
    }
    else
    {
        std::cerr << "Error Opening File\n";
    }
}
bool doesEmailExist(const std::string &emailToCheck)
{
    std::ifstream inFile("users.txt");
    std::string line;

    while (std::getline(inFile, line))
    {
        size_t pos = line.find(":");
        if (pos != std::string::npos)
        {
            std::string email = line.substr(0, pos);
            if (email == emailToCheck)
            {
                inFile.close();
                return true;
            }
        }
    }

    inFile.close();
    return false;
}
UserInfo createUser()
{
    UserInfo user;
    std::cout << "Username(Email): ";
    std::cin >> user.email;
    if (!user.isValidEmail())
    {
        std::cout << "Invalid Email. exiting program" << std::endl;
        return user;
    }

    if (doesEmailExist(user.email))
    {
        std::cout << "Email already exists. Exiting program." << std::endl;
        return user;
    }
    std::cout << "Passwords Must Contain\n - At least 8 Characters\n - At least one uppercase letter\n - At least one lowercase letter\n - At least one digit\n - At least one special character" << std::endl;
    std::cout << "Enter Desired Password\n";
    // Generera saltat lösenord
    std::cin >> user.password;
    std::string salt = generateSalt();
    std::string saltedPassword = user.password + salt;
    // sha256(user.password);
    sha256(saltedPassword);
    // getPassword(user.password);

    if (!user.isValidPassword())
    {
        std::cout << "Invalid Password. Exiting program" << std::endl;
        return user;
    }
    // Writes to File
    // writeToFile(user);
    writeToHashSaltFile(user);
    return user;
}
void trimWhitespace(std::string &str)
{
    str.erase(0, str.find_first_not_of(" \t\n\r\f\v"));
    str.erase(str.find_last_not_of(" \t\n\r\f\v") + 1);
}
int loggedIn()
{
    std::string login_email;
    std::string login_password;
    // std::fstream pull("users.txt", std::ios::in);
    std::ifstream pull("users_with_salt.txt");
    if (!pull.is_open())
    {
        std::cout << "File not loaded!" << std::endl;
        return -1;
    }
    std::cout << "Enter email: ";
    std::cin >> login_email;
    trimWhitespace(login_email);

    std::string line;
    while (std::getline(pull, line))
    {
        // size_t pos = line.find(":");
        // if (pos != std::string::npos)
        //{
        //  --------- WITHOUT HASHING AND SALTING ---------
        //  std::string stored_email = line.substr(0, pos);
        //  std::string stored_password = line.substr(pos + 1);
        //  if (login_email == stored_email)
        //  {
        //      std::cout << "Enter password: ";
        //      std::cin >> login_password;

        //     while (sha256(login_password) != stored_password)
        //     {
        //         std::cout << "Wrong Password. Try again\nEnter Password: ";
        //         std::cin >> login_password;
        //     }
        //     std::cout << "Login Successful" << std::endl;
        //     pull.close();
        //     pull.open("users.txt", std::ios::in);
        //     return 0;
        // -------------------------------------------------
        std::istringstream iss(line);
        std::string stored_email, stored_password, stored_salt;
        std::getline(iss, stored_email, ':');
        std::getline(iss, stored_password, ':');
        std::getline(iss, stored_salt);
        if (login_email == stored_email)
        {
            std::cout << "Enter password: ";
            std::cin >> login_password;
            std::string saltedPassword = login_password + stored_salt;
            while (sha256(saltedPassword) != stored_password)
            {
                std::cout << saltedPassword << std::endl;
                std::cout << stored_password << std::endl;
                std::cout << "Wrong Password. Try again\nEnter Password: ";
                std::cin >> login_password;
                saltedPassword = login_password + stored_salt;
            }
            std::cout << "Login Successful" << std::endl;
            pull.close();
            pull.open("users_with_salt.txt", std::ios::in);
            return 0;
        }
        //}
    }
    std::cout << "Email not found." << std::endl;
    pull.close();
    return 1;
}
void login()
{
    UserInfo user;
    int choice;
    do
    {
        std::cout << "1. Create User\n2. Test Login\n3. crackPasswords\n4. Exit\n";
        std::cout << "Input: ";
        std::cin >> choice;

        switch (choice)
        {
        case 1:
            user = createUser();
            break;
        case 2:
            loggedIn();
            break;
        case 3:
            // hashPasswords();
            mainCracker();
            break;
        case 4:
            std::cout << "Exiting Program.\n";
            return;
        default:
            std::cout << "Invalid choice. Try again.\n";
        }
        std::cin.clear();
    } while (choice != 3);
}
int main()
{
    std::string salt = generateSalt();

    std::cout << "Salt: " << salt << std::endl;
    login();
    return 0;
}