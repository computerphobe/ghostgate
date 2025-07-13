#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <ctime>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


#define PORT 2222
#define LOGFILE "logs/honeypot.log"

std::string timestamp() {
    time_t now = time(0);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", localtime(&now));
    return std::string(buf);
}

void log(const std::string& message) {
    std::ofstream logFile(LOGFILE, std::ios::app);
    if (logFile) {
        logFile << "[" << timestamp() << "] " << message << std::endl;
    }
}

void handleConnection(int clientSocket, sockaddr_in clientAddr) {
    char buffer[1024] = {0};

    std::string clientIP = inet_ntoa(clientAddr.sin_addr);
    int clientPort = ntohs(clientAddr.sin_port);

    log("Connection from " + clientIP + ":" + std::to_string(clientPort));

    std::string banner = "Fake SSH Service\nUsername: ";
    send(clientSocket, banner.c_str(), banner.length(), 0);
    read(clientSocket, buffer, 1024);
    std::string username(buffer);
    username.erase(username.find_last_not_of(" \n\r\t") + 1);

    memset(buffer, 0, sizeof(buffer));
    std::string passPrompt = "Password: ";
    send(clientSocket, passPrompt.c_str(), passPrompt.length(), 0);
    read(clientSocket, buffer, 1024);
    std::string password(buffer);
    password.erase(password.find_last_not_of(" \n\r\t") + 1);

    log("Credentials from " + clientIP + ": " + username + "/" + password);

    std::string denied = "Access Denied.\n";
    send(clientSocket, denied.c_str(), denied.length(), 0);

    close(clientSocket);
}

int main() {
    int server_fd, clientSocket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    mkdir("logs", 0777);  // ensure logs directory exists

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Allow address reuse
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind to port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Honeypot listening on port " << PORT << "..." << std::endl;

    while (true) {
        clientSocket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (clientSocket >= 0) {
            handleConnection(clientSocket, address);
        }
    }

    return 0;
}
