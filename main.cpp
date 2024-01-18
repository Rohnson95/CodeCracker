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
        userFile << " Email: " << user.email << " Password: " << user.password << "\n";
        userFile << "-----------------------------------\n";
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
void getPassword(std::string &password)
{
    char ch;
    while ((ch = _getch()) != 13)
    {
        if (ch == 8)
        {
            if (!password.empty())
            {
                _putch('\b');
                _putch(' ');
                _putch('\b');
                password.pop_back();
            }
        }
        else if (isprint(ch))
        {
            std::cout << '*';
            password.push_back(ch);
        }
    }
    password.erase(std::remove(password.begin(), password.end(), '\n'), password.end());
    password.erase(std::remove(password.begin(), password.end(), '\r'), password.end());

    std::cout << std::endl;
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
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

    // Changes Characters of password
    getPassword(user.password);

    if (!user.isValidPassword())
    {
        std::cout << "Invalid Password. Exiting program" << std::endl;
        return user;
    }
    // Writes to File
    writeToFile(user);

    return user;
}

bool loggedIn(UserInfo &user)
{
    std::cout << "Enter Email: " << std::endl;
    std::cin >> user.email;
    std::cout << "Enter Password: ";
    getPassword(user.password);

    user.password.erase(std::remove(user.password.begin(), user.password.end(), '\n'), user.password.end());
    std::ifstream inFile("users.txt");
    std::string line;
    bool isUserFound = false;

    while (std::getline(inFile, line))
    {
        line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
        line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());

        // Check if the line contains both email and password
        size_t emailPos = line.find(" Email: " + user.email);
        size_t passwordPos = line.find(" Password: " + user.password);

        if (emailPos != std::string::npos && passwordPos != std::string::npos)
        {
            isUserFound = true;
            break;
        }
    }

    inFile.close();
    if (isUserFound)
    {
        std::cout << "Successful Login" << std::endl;
    }
    else
    {
        std::cout << "---Login Failed---\n"
                  << std::endl;
    }

    return isUserFound;
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
        // std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    } while (choice != 3);
}
int main()
{
    login();
    return 0;
}