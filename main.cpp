#include <iostream>
#include <vector>
#include <string>
#include <regex>
#include <fstream>
#include <conio.h>
#include <limits>
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

void writeToFile(const UserInfo &user)
{
    std::ofstream userFile("users.txt", std::ios::app);

    if (userFile.is_open())
    {
        userFile << user.email << " " << user.password;
        userFile << "\n";
        userFile.close();
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
        if (line.find("Email: " + emailToCheck) != std::string::npos)
        {
            inFile.close();
            return true;
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
    std::cin >> user.password;
    // getPassword(user.password);

    if (!user.isValidPassword())
    {
        std::cout << "Invalid Password. Exiting program" << std::endl;
        return user;
    }
    // Writes to File
    writeToFile(user);

    return user;
}
void trimWhitespace(std::string &str)
{
    str.erase(0, str.find_first_not_of(" \t\n\r\f\v"));
    str.erase(str.find_last_not_of(" \t\n\r\f\v") + 1);
}
int loggedIn(UserInfo &user)
{
    std::string login_email;
    std::string login_password;
    std::fstream pull("users.txt", std::ios::in);
    if (!pull.is_open())
    {
        std::cout << "File not loaded!" << std::endl;
        return -1;
    }
    std::cout << "Enter email: ";
    std::cin >> login_email;
    trimWhitespace(login_email);

    while (pull >> user.email >> user.password)
    {
        if (login_email == user.email)
        {
            std::cout << "Enter password: ";
            std::cin >> login_password;

            while (login_password != user.password)
            {
                std::cout << "Wrong Password. Try again\nEnter Password: ";
                std::cin >> login_password;
            }
            std::cout << "Login Successful" << std::endl;
            pull.close();
            pull.open("users.txt", std::ios::in);
            return 0;
        }
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
        std::cout << "1. Create User\n2. Test Login\n3. Exit\n";
        std::cout << "Input: ";
        std::cin >> choice;

        switch (choice)
        {
        case 1:
            user = createUser();
            break;
        case 2:
            loggedIn(user);
            break;
        case 3:
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
    login();
    return 0;
}