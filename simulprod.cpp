#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <algorithm>
#include <direct.h>  // For _getcwd

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define BUFFER_SIZE 4096
#define PORT 8080

std::string removePort(const std::string& input) {
    std::size_t found = input.find(":443");
    if (found != std::string::npos) {
        return input.substr(0, found);
    }
    return input;
}

void initializeSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanupSSL() {
    EVP_cleanup();
}

SSL_CTX* createSSLContext() {
    const SSL_METHOD* method = SSLv23_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void handleClient(SOCKET clientSocket, SSL_CTX* ctx) {
    char buffer[BUFFER_SIZE];
    int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);

    if (bytesReceived > 0) {
        std::string request(buffer, bytesReceived);
        std::istringstream iss(request);
        std::string requestLine;
        std::getline(iss, requestLine);

        std::cout << "Received request: " << requestLine << std::endl;

        std::string method, host, port;
        std::istringstream requestStream(requestLine);
        requestStream >> method >> host;

        // Handle CONNECT method for HTTPS
        if (method == "CONNECT") {
            size_t colonPos = host.find(':');
            if (colonPos != std::string::npos) {
                port = host.substr(colonPos + 1);
                host = host.substr(0, colonPos);
            } else {
                port = "443";
            }

            std::cout << "Connecting to " << host << ":" << port << std::endl;

            struct addrinfo hints = {};
            struct addrinfo* res;

            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
                std::cerr << "getaddrinfo failed" << std::endl;
                closesocket(clientSocket);
                return;
            }

            SOCKET remoteSocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (remoteSocket == INVALID_SOCKET) {
                std::cerr << "Unable to create socket" << std::endl;
                freeaddrinfo(res);
                closesocket(clientSocket);
                return;
            }

            if (connect(remoteSocket, res->ai_addr, res->ai_addrlen) == SOCKET_ERROR) {
                std::cerr << "Unable to connect to remote host" << std::endl;
                closesocket(remoteSocket);
                freeaddrinfo(res);
                closesocket(clientSocket);
                return;
            }

            freeaddrinfo(res);

            std::string response = "HTTP/1.1 200 Connection Established\r\n\r\n";
            send(clientSocket, response.c_str(), response.length(), 0);

            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, remoteSocket);

            if (SSL_connect(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                closesocket(remoteSocket);
                closesocket(clientSocket);
                return;
            }

            // Tunnel data between client and remote server
            while (true) {
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(clientSocket, &readfds);
                FD_SET(remoteSocket, &readfds);

                int maxfd = std::max(clientSocket, remoteSocket);
                int activity = select(maxfd + 1, &readfds, NULL, NULL, NULL);

                if (activity < 0) {
                    std::cerr << "select error" << std::endl;
                    break;
                }

                if (FD_ISSET(clientSocket, &readfds)) {
                    bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);
                    if (bytesReceived <= 0) {
                        break;
                    }
                    SSL_write(ssl, buffer, bytesReceived);
                }

                if (FD_ISSET(remoteSocket, &readfds)) {
                    bytesReceived = SSL_read(ssl, buffer, BUFFER_SIZE);
                    if (bytesReceived <= 0) {
                        break;
                    }
                    send(clientSocket, buffer, bytesReceived, 0);
                }
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            closesocket(remoteSocket);
        }
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

    initializeSSL();
    SSL_CTX* ctx = createSSLContext();

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        cleanupSSL();
        return 1;
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        WSACleanup();
        cleanupSSL();
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
        cleanupSSL();
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        cleanupSSL();
        return 1;
    }

    std::cout << "Server listening on port " << PORT << "..." << std::endl;

    while (true) {
        SOCKET clientSocket = accept(serverSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed" << std::endl;
            continue;
        }

        handleClient(clientSocket, ctx);
    }

    closesocket(serverSocket);
    WSACleanup();
    cleanupSSL();
    return 1;
}
