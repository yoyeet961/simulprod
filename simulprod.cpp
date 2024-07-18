#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define BUFFER_SIZE 8192
#define PORT 443  // Change to 443 for HTTPS

void print_openssl_error() {
    unsigned long errCode;
    while ((errCode = ERR_get_error()) != 0) {
        char *err = ERR_error_string(errCode, NULL);
        std::cerr << "OpenSSL error: " << err << std::endl;
    }
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        print_openssl_error();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX* ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load certificate file" << std::endl;
        print_openssl_error();
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load private key" << std::endl;
        print_openssl_error();
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        std::cerr << "Private key does not match the certificate public key" << std::endl;
        print_openssl_error();
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4") != 1) {
        std::cerr << "Failed to set cipher list" << std::endl;
        print_openssl_error();
        exit(EXIT_FAILURE);
    }

    std::cout << "SSL context configured successfully" << std::endl;
}


void serveFile(const std::string& host, const std::string& path, SSL* ssl) {
    std::string fullPath = "pages/" + host + path;

    std::cout << "Attempting to serve file: " << fullPath << std::endl;

    std::ifstream file(fullPath, std::ios::binary);
    if (!file) {
        std::cerr << "File not found: " << fullPath << std::endl;
        fullPath = "pages/default" + path;
        file.open(fullPath, std::ios::binary);
        if (!file) {
            std::cerr << "File not found in default directory: " << fullPath << std::endl;
            std::string notFound = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>";
            SSL_write(ssl, notFound.c_str(), notFound.length());
            return;
        }
    }

    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + std::to_string(fileSize) + "\r\n\r\n" + content;
    SSL_write(ssl, response.c_str(), response.length());
}

void handleClient(SSL* ssl) {
    char buffer[BUFFER_SIZE];
    int bytesReceived = SSL_read(ssl, buffer, BUFFER_SIZE);

    if (bytesReceived > 0) {
        std::string request(buffer, bytesReceived);
        std::istringstream iss(request);
        std::string requestLine;
        std::getline(iss, requestLine);

        std::cout << "Received request: " << requestLine << std::endl;

        std::string method, fullUrl, httpVersion;
        std::istringstream requestStream(requestLine);
        requestStream >> method >> fullUrl >> httpVersion;

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

        size_t colonPos = host.find(':');
        if (colonPos != std::string::npos) {
            host = host.substr(0, colonPos);
        }

        std::string path;
        size_t pathStart = fullUrl.find('/', fullUrl.find("//") + 2);
        if (pathStart != std::string::npos) {
            path = fullUrl.substr(pathStart);
        } else {
            path = "/";
        }

        if (path == "/" || path.empty()) {
            path = "/index.html";
        }

        std::cout << "Serving path: " << path << " for host: " << host << std::endl;

        serveFile(host, path, ssl);
    }
}

bool is_ssl_connection(SOCKET socket) {
    char buffer[1024];
    int bytes_received = recv(socket, buffer, sizeof(buffer) - 1, MSG_PEEK);
    buffer[bytes_received] = '\0';  // Null-terminate the string

    std::cout << "Received " << bytes_received << " bytes" << std::endl;
    std::cout << "First 10 bytes: ";
    for (int i = 0; i < bytes_received && i < 10; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)buffer[i] << " ";
    }
    std::cout << std::dec << std::endl;

    if (bytes_received <= 0) {
        std::cerr << "Error receiving data or connection closed" << std::endl;
        return false;
    }

    if (strncmp(buffer, "CONNECT ", 8) == 0) {
        std::cout << "CONNECT request detected, handling as SSL" << std::endl;
        return true;
    }
    
    // Check if the first byte is a valid SSL/TLS record type
    bool is_ssl = (buffer[0] >= 0x14 && buffer[0] <= 0x17) || buffer[0] == 0x16;
    std::cout << "Is SSL connection: " << (is_ssl ? "Yes" : "No") << std::endl;
    return is_ssl;
}

void handle_connect(SOCKET clientSocket) {
    char buffer[1024];
    int bytes_received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    buffer[bytes_received] = '\0';

    // Send "200 Connection established" response
    const char* response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(clientSocket, response, strlen(response), 0);
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }

    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

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
    //serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Or the IP address of your domain

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

    std::cout << "Server listening on port " << PORT << std::endl;

    while (true) {

        SOCKET clientSocket = accept(serverSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed" << std::endl;
            continue;
        }

        std::cout << "New connection accepted" << std::endl;

        if (PORT == 443) {
            if (is_ssl_connection(clientSocket)) {
                std::cout << "Initiating SSL handshake" << std::endl;
                
                // Handle CONNECT request if present
                handle_connect(clientSocket);

                SSL* ssl = SSL_new(ctx);
                SSL_set_fd(ssl, clientSocket);

                int ret = SSL_accept(ssl);
                if (ret <= 0) {
                    std::cerr << "SSL_accept failed" << std::endl;
                    print_openssl_error();
                } else {
                    std::cout << "SSL handshake successful" << std::endl;
                    handleClient(ssl);
                }

                SSL_shutdown(ssl);
                SSL_free(ssl);
            } else {
                std::cerr << "Non-SSL connection received on HTTPS port. Closing." << std::endl;
            }
        } //else {
        //     // Handle HTTP connection
        //     handleHttpClient(clientSocket);
        // }

        closesocket(clientSocket);
    }

    SSL_CTX_free(ctx);
    cleanup_openssl();
    closesocket(serverSocket);
    WSACleanup();
    return 0;
}