#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <ctime>
#include <vector>
#include <map>
#include <utility> // For std::pair

// Windows-specific headers for Winsock
#include <winsock2.h>
#include <ws2tcpip.h>

// For mkdir equivalent on Windows (_mkdir)
#include <direct.h>

// For error handling (errno for perror equivalent)
#include <cerrno>

// For exit (EXIT_FAILURE)
#include <cstdlib>

// For _stat on Windows
#include <sys/stat.h>

#pragma comment(lib, "Ws2_32.lib")

#define SSH_PORT 2222
#define TELNET_PORT 23
#define FTP_PORT 21
#define HTTP_PORT 8080

#define LOGFILE "logs/honeypot.log"

// --- Utility Functions ---
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
    struct _stat info;
    if (_stat("logs", &info) != 0) {
        if (_mkdir("logs") != 0) {
            std::cerr << "Failed to create logs directory: " << strerror(errno) << std::endl;
        }
    }

    std::ofstream logFile(LOGFILE, std::ios::app);
    if (logFile) {
        logFile << "[" << timestamp() << "] " << message << std::endl;
    } else {
        std::cerr << "Error: Could not open log file " << LOGFILE << std::endl;
    }
}

void printWinsockError(const char* funcName) {
    int wsError = WSAGetLastError();
    std::cerr << funcName << " failed with error: " << wsError << std::endl;
}

// --- NEW HELPER FUNCTION: Read a line from the socket ---
// Reads characters until a newline character ('\n') is encountered or buffer is full/error.
// Handles both LF and CRLF line endings.
std::string readLine(SOCKET sock) {
    std::string line = "";
    char buffer;
    int bytesReceived;

    while (true) {
        bytesReceived = recv(sock, &buffer, 1, 0); // Read one byte at a time
        if (bytesReceived == SOCKET_ERROR) {
            // Log the error or handle it as appropriate for your app
            // printWinsockError("readLine recv");
            return ""; // Error, return empty string
        }
        if (bytesReceived == 0) {
            // Connection closed by peer
            return line; // Return what's been read so far
        }

        if (buffer == '\n') {
            // Found newline, we're done with the line
            break;
        }
        if (buffer != '\r') { // Ignore carriage returns if present
            line += buffer;
        }
    }
    return line;
}


// --- Protocol Handlers ---
void handleSshLikeConnection(SOCKET clientSocket, sockaddr_in clientAddr) {
    std::string clientIP = inet_ntoa(clientAddr.sin_addr);
    int clientPort = ntohs(clientAddr.sin_port);

    log("SSH-like connection from " + clientIP + ":" + std::to_string(clientPort) + " on port " + std::to_string(SSH_PORT));

    std::string banner = "Fake SSH Service\nUsername: ";
    send(clientSocket, banner.c_str(), banner.length(), 0);
    
    std::string username = readLine(clientSocket); // Use readLine here
    if (username.empty()) { // Check if connection closed or error occurred
        log("Connection closed or error during username receive from " + clientIP);
        closesocket(clientSocket);
        return;
    }
    // No need for erase here, readLine already handles trimming \r\n
    // username.erase(username.find_last_not_of(" \n\r\t") + 1); // Remove this line

    std::string passPrompt = "Password: ";
    send(clientSocket, passPrompt.c_str(), passPrompt.length(), 0);
    
    std::string password = readLine(clientSocket); // Use readLine here
    if (password.empty()) { // Check if connection closed or error occurred
        log("Connection closed or error during password receive from " + clientIP);
        closesocket(clientSocket);
        return;
    }
    // No need for erase here
    // password.erase(password.find_last_not_of(" \n\r\t") + 1); // Remove this line

    log("Credentials from " + clientIP + ": " + username + "/" + password);

    std::string denied = "Access Denied.\n";
    send(clientSocket, denied.c_str(), denied.length(), 0);

    closesocket(clientSocket);
}

void handleTelnetConnection(SOCKET clientSocket, sockaddr_in clientAddr) {
    std::string clientIP = inet_ntoa(clientAddr.sin_addr);
    int clientPort = ntohs(clientAddr.sin_port);
    log("Telnet connection from " + clientIP + ":" + std::to_string(clientPort) + " on port " + std::to_string(TELNET_PORT));
    std::string banner = "Welcome to the fake Telnet server.\r\nLogin: ";
    send(clientSocket, banner.c_str(), banner.length(), 0);

    std::string username = readLine(clientSocket); // Capture login
    log("Telnet login attempt from " + clientIP + ": " + username);
    std::string passPrompt = "Password: \r\n";
    send(clientSocket, passPrompt.c_str(), passPrompt.length(), 0);
    std::string password = readLine(clientSocket); // Capture password
    log("Telnet password attempt from " + clientIP + ": " + password);

    std::string response = "Login incorrect\r\n";
    send(clientSocket, response.c_str(), response.length(), 0);
    closesocket(clientSocket);
}

void handleFtpConnection(SOCKET clientSocket, sockaddr_in clientAddr) {
    std::string clientIP = inet_ntoa(clientAddr.sin_addr);
    int clientPort = ntohs(clientAddr.sin_port);
    log("FTP connection from " + clientIP + ":" + std::to_string(clientPort) + " on port " + std::to_string(FTP_PORT));
    std::string banner = "220 Fake FTP Server ready.\r\n";
    send(clientSocket, banner.c_str(), banner.length(), 0);

    std::string command_line;
    std::string last_user = ""; // To store username for PASS command

    while (true) {
        command_line = readLine(clientSocket);
        if (command_line.empty()) { // Connection closed or error
            log("FTP connection closed by " + clientIP);
            break;
        }

        log("FTP command from " + clientIP + ": " + command_line);

        // Convert command to uppercase for case-insensitive comparison
        std::string cmd_upper = command_line;
        for (char &c : cmd_upper) {
            c = toupper(c);
        }

        if (cmd_upper.rfind("USER ", 0) == 0) { // Starts with "USER "
            last_user = command_line.substr(5); // Extract username
            log("FTP Username captured: " + last_user + " from " + clientIP);
            std::string response = "331 Password required for " + last_user + ".\r\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        } else if (cmd_upper.rfind("PASS ", 0) == 0) { // Starts with "PASS "
            std::string password = command_line.substr(5); // Extract password
            log("FTP Password captured: " + password + " for user " + last_user + " from " + clientIP);
            std::string response = "530 Login incorrect.\r\n";
            send(clientSocket, response.c_str(), response.length(), 0);
            break; // Close connection after failed login
        } else if (cmd_upper == "QUIT" || cmd_upper == "BYE") {
            std::string response = "221 Goodbye.\r\n";
            send(clientSocket, response.c_str(), response.length(), 0);
            break;
        } else if (cmd_upper == "SYST") {
            std::string response = "215 UNIX Type: L8\r\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        } else if (cmd_upper == "FEAT") {
            std::string response = "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n MFMT\r\n REST STREAM\r\n SIZE\r\n MLST type*;size*;sizd*;modify*;perm*;\r\n MLSD\r\n UTF8\r\n CLNT\r\n TVFS\r\n\r\n"; // Notice the double \r\n at the end of feature list
            send(clientSocket, response.c_str(), response.length(), 0);
        } else {
            std::string response = "500 Syntax error, command unrecognized.\r\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        }
    }
    closesocket(clientSocket);
}

void handleHttpConnection(SOCKET clientSocket, sockaddr_in clientAddr) {
    std::string clientIP = inet_ntoa(clientAddr.sin_addr);
    int clientPort = ntohs(clientAddr.sin_port);
    log("HTTP connection from " + clientIP + ":" + std::to_string(clientPort) + " on port " + std::to_string(HTTP_PORT));
    
    std::string request_line = "";
    std::string full_request = "";
    while (true) {
        request_line = readLine(clientSocket);
        if (request_line.empty()) { // End of stream or error
            break;
        }
        full_request += request_line + "\n"; // Reconstruct with newlines for logging
        if (request_line == "") { // Empty line signifies end of HTTP headers
            break;
        }
    }

    if (!full_request.empty()) {
        log("HTTP Request from " + clientIP + ":\n" + full_request);
        // Basic parsing for HTTP Basic Auth
        std::istringstream iss(full_request);
        std::string line;
        while (std::getline(iss, line, '\n')) {
            if (line.rfind("Authorization: Basic ", 0) == 0) {
                std::string encoded_creds = line.substr(line.find("Basic ") + 6);
                // In a real scenario, you'd base64 decode this. For a honeypot, logging the encoded is fine.
                log("HTTP Basic Auth captured from " + clientIP + ": " + encoded_creds);
                break;
            }
        }
    } else {
        log("No HTTP request received from " + clientIP);
    }

    std::string response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 29\r\n"
        "\r\n"
        "<h1>Welcome to the Honeypot!</h1>";
    send(clientSocket, response.c_str(), response.length(), 0);
    closesocket(clientSocket);
}


// --- Main Function ---
int main() {
    WSADATA wsaData;
    int iResult;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    // Ensure logs directory exists
    struct _stat info;
    if (_stat("logs", &info) != 0) {
        if (_mkdir("logs") != 0) {
            std::cerr << "Failed to create logs directory: " << strerror(errno) << std::endl;
        }
    }

    std::vector<int> ports = {SSH_PORT, TELNET_PORT, FTP_PORT, HTTP_PORT};
    std::map<SOCKET, int> listeningSockets;
    SOCKET max_sd = INVALID_SOCKET;

    for (int port : ports) {
        SOCKET server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_fd == INVALID_SOCKET) {
            printWinsockError(("socket creation for port " + std::to_string(port)).c_str());
            for (auto const& pair : listeningSockets) {
                closesocket(pair.first);
            }
            WSACleanup();
            return 1;
        }

        int opt = 1;
        iResult = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        if (iResult == SOCKET_ERROR) {
            printWinsockError(("setsockopt for port " + std::to_string(port)).c_str());
            closesocket(server_fd);
            continue;
        }

        sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        iResult = bind(server_fd, (struct sockaddr *)&address, sizeof(address));
        if (iResult == SOCKET_ERROR) {
            printWinsockError(("bind for port " + std::to_string(port)).c_str());
            closesocket(server_fd);
            continue;
        }

        iResult = listen(server_fd, SOMAXCONN); 
        if (iResult == SOCKET_ERROR) {
            printWinsockError(("listen for port " + std::to_string(port)).c_str());
            closesocket(server_fd);
            continue;
        }

        listeningSockets[server_fd] = port;
        if (server_fd > max_sd) { 
            max_sd = server_fd;
        }
        std::cout << "Honeypot listening on port " << port << "..." << std::endl;
        log("Honeypot started listening on port " + std::to_string(port));
    }

    if (listeningSockets.empty()) {
        std::cerr << "No listening sockets could be created. Exiting." << std::endl;
        WSACleanup();
        return 1;
    }

    std::cout << "Logs will be written to: " << LOGFILE << std::endl;

    while (true) {
        fd_set read_fds;
        FD_ZERO(&read_fds);

        for (auto const& pair : listeningSockets) {
            FD_SET(pair.first, &read_fds);
        }

        iResult = select(0, &read_fds, NULL, NULL, NULL);

        if (iResult == SOCKET_ERROR) {
            printWinsockError("select");
            break; 
        }
        
        for (auto const& pair : listeningSockets) {
            SOCKET current_server_fd = pair.first;
            int current_port = pair.second;

            if (FD_ISSET(current_server_fd, &read_fds)) {
                sockaddr_in clientAddr;
                int addrlen = sizeof(clientAddr);
                SOCKET clientSocket = accept(current_server_fd, (struct sockaddr *)&clientAddr, &addrlen);
                if (clientSocket == INVALID_SOCKET) {
                    printWinsockError("accept");
                    continue;
                }

                switch (current_port) {
                    case SSH_PORT:
                        handleSshLikeConnection(clientSocket, clientAddr);
                        break;
                    case TELNET_PORT:
                        handleTelnetConnection(clientSocket, clientAddr);
                        break;
                    case FTP_PORT:
                        handleFtpConnection(clientSocket, clientAddr);
                        break;
                    case HTTP_PORT:
                        handleHttpConnection(clientSocket, clientAddr);
                        break;
                    default:
                        log("Unknown port connection on " + std::to_string(current_port) + " from " + inet_ntoa(clientAddr.sin_addr));
                        closesocket(clientSocket);
                        break;
                }
            }
        }
    }

    for (auto const& pair : listeningSockets) {
        closesocket(pair.first);
    }
    WSACleanup();

    return 0;
}