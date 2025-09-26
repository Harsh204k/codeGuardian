#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <memory>
#include <fstream>
#include <ctime>

using namespace std;

class UserManager {
private:
    char* userDatabase[100]; // Array of user data
    int userCount;

public:
    UserManager() : userCount(0) {}

    // Buffer overflow vulnerability - strcpy without bounds checking
    void addUser(const char* username) {
        if (userCount < 100) {
            userDatabase[userCount] = new char[32];
            strcpy(userDatabase[userCount], username); // CPP-BUFFER-001
            userCount++;
            cout << "User added: " << username << endl;
        }
    }

    // Use after free vulnerability
    void removeUser(int index) {
        if (index >= 0 && index < userCount) {
            delete[] userDatabase[index];
            // Forgot to set pointer to nullptr - use after free possible
            cout << "User removed at index " << index << endl;
        }
    }

    // Access potentially freed memory
    void printUser(int index) {
        if (index >= 0 && index < userCount) {
            cout << "User: " << userDatabase[index] << endl; // CPP-UAF-001
        }
    }
};

int main(int argc, char* argv[]) {
    cout << "=== Vulnerable C++ Application Demo ===" << endl;

    UserManager userMgr;

    // Get user input from command line
    string userInput = (argc > 1) ? argv[1] : "admin";

    // Buffer overflow with fixed-size buffer
    char buffer[64];
    strcpy(buffer, userInput.c_str()); // CPP-BUFFER-002
    cout << "Buffer content: " << buffer << endl;

    // Format string vulnerability
    char formatBuffer[256];
    sprintf(formatBuffer, userInput.c_str()); // CPP-FORMAT-001
    printf(formatBuffer);

    // Command injection vulnerability
    string cmd = "ls -la " + userInput;
    system(cmd.c_str()); // CPP-CMDI-001

    // Integer overflow
    int size = atoi(userInput.c_str());
    if (size > 0) {
        char* largeBuffer = new char[size * 1000000]; // CPP-INT-001
        cout << "Allocated buffer of size: " << (size * 1000000) << endl;
        delete[] largeBuffer;
    }

    // Null pointer dereference
    char* ptr = nullptr;
    if (userInput == "crash") {
        ptr = nullptr; // Explicitly set to null
    }
    *ptr = 'A'; // CPP-NULLPTR-001

    // Insecure random number generation
    srand(time(NULL)); // Weak seed
    int randomValue = rand() % 100; // CPP-WEAKRAND-001
    cout << "Random value: " << randomValue << endl;

    // Demonstrate use after free
    userMgr.addUser("alice");
    userMgr.addUser("bob");
    userMgr.removeUser(0);
    userMgr.printUser(0); // Accessing freed memory

    // File operation vulnerability - path traversal
    string filename = "data/" + userInput;
    ifstream file(filename.c_str()); // CPP-PATH-001
    if (file.is_open()) {
        string line;
        while (getline(file, line)) {
            cout << line << endl;
        }
        file.close();
    }

    // Memory leak - forgot to free memory
    char* leakPtr = new char[100];
    strcpy(leakPtr, "This memory will leak"); // CPP-MEMLEAK-001

    cout << "Application completed" << endl;
    return 0;
}
