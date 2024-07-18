#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <direct.h>  // For _getcwd

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 4096
#define PORT 8080

std::string removePort(const std::string& input) {
    std::size_t found = input.find(":443");
    if (found != std::string::npos) {
        return input.substr(0, found);
    }
    return input;
}

std::string getFileExtension(const std::string& filename) {
    size_t dotPos = filename.find_last_of('.');
    if (dotPos != std::string::npos) {
        return filename.substr(dotPos);
    }
    return "";
}

std::string getMimeType(const std::string& filename) {
    std::string extension = getFileExtension(filename);
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    
    if (extension == ".html" || extension == ".htm") return "text/html";
    if (extension == ".css") return "text/css";
    if (extension == ".js") return "application/javascript";
    if (extension == ".jpg" || extension == ".jpeg") return "image/jpeg";
    if (extension == ".png") return "image/png";
    if (extension == ".gif") return "image/gif";
    return "application/octet-stream";
}

void serveFile(const std::string& host, const std::string& path, SOCKET clientSocket) {
    std::string fullPath = "pages/" + host + path;

    std::cout << "Attempting to serve file: " << fullPath << std::endl;

    std::ifstream file(fullPath, std::ios::binary);
    if (!file) {
        std::cerr << "File not found: " << fullPath << std::endl;
        // Try serving from a default directory if host-specific file is not found
        fullPath = "pages/default" + path;
        file.open(fullPath, std::ios::binary);
        if (!file) {
            std::cerr << "File not found in default directory: " << fullPath << std::endl;
            std::string notFound = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>";
            send(clientSocket, notFound.c_str(), notFound.length(), 0);
            return;
        }
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> fileContent(fileSize);
    file.read(fileContent.data(), fileSize);

    std::string mimeType = getMimeType(fullPath);
    std::string header = "HTTP/1.1 200 OK\r\nContent-Type: " + mimeType + "\r\nContent-Length: " + std::to_string(fileSize) + "\r\n\r\n";
    send(clientSocket, header.c_str(), header.length(), 0);
    send(clientSocket, fileContent.data(), fileContent.size(), 0);

    std::cout << "File served successfully: " << fullPath << std::endl;
}

void handleClient(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);

    if (bytesReceived > 0) {
        std::string request(buffer, bytesReceived);
        std::istringstream iss(request);
        std::string requestLine;
        std::getline(iss, requestLine);

        std::cout << "Received request: " << requestLine << std::endl;

        // Extract method, full URL, and HTTP version
        std::string method, fullUrl, httpVersion;
        std::istringstream requestStream(requestLine);
        requestStream >> method >> fullUrl >> httpVersion;

        std::cout << "Method: " << method << std::endl;
        std::cout << "Full URL: " << fullUrl << std::endl;
        std::cout << "HTTP Version: " << httpVersion << std::endl;

        // Extract host from headers
        std::string host;
        std::string line;
        while (std::getline(iss, line) && line != "\r") {
            if (line.substr(0, 5) == "Host:") {
                host = line.substr(6);
                host.erase(0, host.find_first_not_of(" \t"));
                host.erase(host.find_last_not_of(" \t\r\n") + 1);
                break;
            }
        }

        host = removePort(host);

        std::cout << "Host: " << host << std::endl;

        // Remove port from host if present
        size_t colonPos = host.find(':');
        if (colonPos != std::string::npos) {
            host = host.substr(0, colonPos);
        }

        // Extract path from full URL
        std::string path;
        size_t pathStart = fullUrl.find('/', fullUrl.find("//") + 2);
        if (pathStart != std::string::npos) {
            path = fullUrl.substr(pathStart);
        } else {
            path = "/";
        }

        // If path is empty or just "/", serve index.html
        if (path == "/" || path.empty()) {
            path = "/index.html";
        }

        std::cout << "Serving path: " << path << " for host: " << host << std::endl;

        serveFile(host, path, clientSocket);
    }

    closesocket(clientSocket);
}

int main() {
    char cwd[1024];
    if (_getcwd(cwd, sizeof(cwd)) != NULL) {
        std::cout << "Current working directory: " << cwd << std::endl;
    } else {
        std::cerr << "Unable to get current working directory" << std::endl;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server listening on port " << PORT << "..." << std::endl;

    while (true) {
        SOCKET clientSocket = accept(serverSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed" << std::endl;
            continue;
        }

        handleClient(clientSocket);
    }

    closesocket(serverSocket);
    WSACleanup();
    return 1;
}