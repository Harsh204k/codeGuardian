#include <iostream>
#include <cstring>
#include <cstdlib>

int main() {
    char buffer[10];
    char input[100];
    
    // Buffer overflow vulnerability
    strcpy(buffer, input);
    
    // Format string vulnerability
    printf(input);
    
    // Command injection
    system("ls " + std::string(input));
    
    // Use after free
    char* ptr = new char[10];
    delete ptr;
    *ptr = 'a';  // Use after free
    
    // Null pointer dereference
    char* nullPtr = nullptr;
    *nullPtr = 'x';
    
    return 0;
}
