// C++ Test Dataset - Security Vulnerabilities
// File: vulnerable_cpp.cpp

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <fstream>

class VulnerableCPPApp {
public:
    // VULNERABILITY 1: Buffer Overflow
    void unsafeStringCopy(const char* input) {
        char buffer[100];
        strcpy(buffer, input);  // Buffer overflow vulnerability
        std::cout << "Buffer content: " << buffer << std::endl;
    }
    
    // VULNERABILITY 2: Use After Free
    void useAfterFree() {
        char* ptr = (char*)malloc(100);
        free(ptr);
        
        // Use after free vulnerability
        strcpy(ptr, "This is dangerous!");
        std::cout << ptr << std::endl;
    }
    
    // VULNERABILITY 3: Memory Leak
    void memoryLeak() {
        for(int i = 0; i < 1000; i++) {
            char* data = new char[1024];
            // Memory leak - no delete[]
            memset(data, 0, 1024);
        }
    }
    
    // VULNERABILITY 4: Format String Vulnerability
    void formatStringVuln(const char* userInput) {
        printf(userInput);  // Format string vulnerability
    }
    
    // VULNERABILITY 5: Integer Overflow
    int integerOverflow(int a, int b) {
        return a + b;  // No overflow check
    }
    
    // VULNERABILITY 6: Unsafe File Operations
    void unsafeFileRead(const char* filename) {
        std::ifstream file(filename);  // No path validation
        if(file.is_open()) {
            std::string line;
            while(getline(file, line)) {
                std::cout << line << std::endl;
            }
            file.close();
        }
    }
    
    // VULNERABILITY 7: Command Injection
    void executeCommand(const char* userCmd) {
        char command[256];
        sprintf(command, "ls %s", userCmd);  // Command injection
        system(command);
    }
    
    // VULNERABILITY 8: Null Pointer Dereference
    void nullPointerDeref(char* ptr) {
        if(ptr == nullptr) {
            return;
        }
        // Potential null pointer dereference
        *ptr = 'A';
    }
};

int main() {
    VulnerableCPPApp app;
    
    // Test the vulnerable functions
    app.unsafeStringCopy("This could cause buffer overflow if too long!");
    app.useAfterFree();
    app.memoryLeak();
    
    return 0;
}
