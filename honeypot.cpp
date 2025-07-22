#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <ctime>

// Windows-specific headers for Winsock
#include <winsock2.h> // Core Winsock functions, types, and definitions
#include <ws2tcpip.h> // For newer functions like InetPton (IPv6 support, though not used extensively here)

// For mkdir equivalent on Windows (_mkdir)
#include <direct.h>

// For error handling (errno for perror equivalent)
#include <cerrno>

// For exit (EXIT_FAILURE)
#include <cstdlib>

// For _stat on Windows
#include <sys/stat.h> // This header is correct for _stat function on Windows

// IMPORTANT: Link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib") // This line tells MSVC to automatically link Ws2_32.lib

#define PORT 2222
#define LOGFILE "logs/honeypot.log"

std::string timestamp() {
    time_t now = time(0);
    char buf[80];
    struct tm *ltm = localtime(&now); 
    if (ltm == NULL) {
        return "ERROR_TIMESTAMP";
    }
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", ltm);
    return std::string(buf);
}

void log(const std::string& message) {
    // Correct usage of _stat function
    struct _stat info; // Declare an instance of the _stat struct
    if (_stat("logs", &info) != 0) { // Call the _stat function with the path and address of the struct
        // Directory does not exist, try to create it
        if (_mkdir("logs") != 0) {
            std::cerr << "Failed to create logs directory: " << strerror(errno) << std::endl;
            // Handle error, e.g., exit or continue without logging
        }
    }

    std::ofstream logFile(LOGFILE, std::ios::app);
    if (logFile) {
        logFile << "[" << timestamp() << "] " << message << std::endl;
    } else {
        std::cerr << "Error: Could not open log file " << LOGFILE << std::endl;
    }
}

// Function to get last error and print Winsock-specific message
void printWinsockError(const char* funcName) {
    int wsError = WSAGetLastError();
    std::cerr << funcName << " failed with error: " << wsError << std::endl;
}

void handleConnection(SOCKET clientSocket, sockaddr_in clientAddr) {
    char buffer[1024] = {0};

    std::string clientIP = inet_ntoa(clientAddr.sin_addr);
    int clientPort = ntohs(clientAddr.sin_port);

    log("Connection from " + clientIP + ":" + std::to_string(clientPort));

    std::string banner = "Fake SSH Service\nUsername: ";
    send(clientSocket, banner.c_str(), banner.length(), 0);
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
    } else {
        log("Error or connection closed during username receive from " + clientIP);
        closesocket(clientSocket);
        return;
    }
    std::string username(buffer);
    username.erase(username.find_last_not_of(" \n\r\t") + 1);

    memset(buffer, 0, sizeof(buffer));
    std::string passPrompt = "Password: ";
    send(clientSocket, passPrompt.c_str(), passPrompt.length(), 0);
    bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
    } else {
        log("Error or connection closed during password receive from " + clientIP);
        closesocket(clientSocket);
        return;
    }
    std::string password(buffer);
    password.erase(password.find_last_not_of(" \n\r\t") + 1);

    log("Credentials from " + clientIP + ": " + username + "/" + password);

    std::string denied = "Access Denied.\n";
    send(clientSocket, denied.c_str(), denied.length(), 0);

    closesocket(clientSocket);
}

int main() {
    WSADATA wsaData;
    SOCKET server_fd, clientSocket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    int iResult;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    // Correct usage of _stat function
    struct _stat info; // Declare an instance of the _stat struct
    if (_stat("logs", &info) != 0) { // Call the _stat function
        if (_mkdir("logs") != 0) {
            std::cerr << "Failed to create logs directory: " << strerror(errno) << std::endl;
            // Optionally, handle error, e.g., exit or continue without logging
        }
    }

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd == INVALID_SOCKET) {
        printWinsockError("socket");
        WSACleanup();
        return 1;
    }

    // Allow address reuse
    iResult = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    if (iResult == SOCKET_ERROR) {
        printWinsockError("setsockopt");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind to port
    iResult = bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    if (iResult == SOCKET_ERROR) {
        printWinsockError("bind");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    // Listen for incoming connections
    iResult = listen(server_fd, 3);
    if (iResult == SOCKET_ERROR) {
        printWinsockError("listen");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    std::cout << "Honeypot listening on port " << PORT << "..." << std::endl;
    std::cout << "Logs will be written to: " << LOGFILE << std::endl;

    while (true) {
        clientSocket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (clientSocket == INVALID_SOCKET) {
            printWinsockError("accept");
            continue;
        } else {
            handleConnection(clientSocket, address);
        }
    }

    closesocket(server_fd);
    WSACleanup();

    return 0;
}