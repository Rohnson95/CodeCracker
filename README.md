# CodeCracker
This program is a simple password management system that allows users to create accounts with secure passwords, log in securely, and even includes a basic password cracker. 

## Features

- **User Account Creation:** Users can create accounts with a valid email address and a secure password.
- **Secure Password Storage:** Passwords are securely hashed using SHA-256 and stored alongside a randomly generated salt for added security.
- **Login System:** Users can log in securely using their email and password combination.
- **Password Strength Checking:** The system ensures that passwords meet certain criteria for strength, including length and character requirements.
- **Password Cracker:** Includes a basic password cracker functionality.

## How to Use

1. **Compile the Code:** Compile the provided code using a C++ compiler.
   
2. **Run the Program:** Execute the compiled program.

3. **Choose an Option:**
   - **Create User:** Choose option 1 to create a new user account.
   - **Test Login:** Option 2 allows existing users to log in.
   - **Crack Passwords:** Option 3 runs the password cracker.

4. **Follow On-Screen Instructions:** Depending on the option chosen, follow the on-screen instructions to create an account, log in, or crack passwords.

## Requirements

- C++ Compiler
- OpenSSL Library

## File Structure

- **passwordCracker.h:** Header file containing declarations for functions related to password cracking.
- **users.txt:** File containing user information (email and hashed password).
- **users_with_salt.txt:** File containing user information with hashed passwords and salts.

## Note

- This is a basic implementation for educational purposes and may not be suitable for production environments.
- Always use strong, unique passwords and secure methods for storing and managing passwords in real-world applications.

---
Feel free to extend and modify this code according to your needs! If you have any questions or suggestions, please don't hesitate to reach out.

# Password Cracker

This program includes a basic password cracker functionality that allows users to input a hash and attempts to find the corresponding password from a sorted list of common passwords.

## Features

- **Hash Passwords:** The program hashes a list of common passwords and sorts them for efficient searching.
- **Password Cracking:** Users can input a hash, and the program will attempt to find the corresponding password.
- **Efficient Search:** Utilizes binary search for quick password lookup.

## How to Use

1. **Compile the Code:** Compile the provided code using a C++ compiler.
   
2. **Run the Program:** Execute the compiled program.

3. **Enter Hash:** Input the hash you want to crack when prompted.

4. **View Result:** The program will display the corresponding password if found, along with the time taken for the operation.

## Requirements

- C++ Compiler
- OpenSSL Library

## File Structure

- **commonPasswords.txt:** File containing a list of common passwords.
- **sorted_common_passwords.txt:** File containing sorted common passwords along with their hashes.
