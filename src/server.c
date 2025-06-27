#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/bn.h>
#include "diffie_hellman.h"

#define PORT 8080
#define BUFFER_SIZE 1024

typedef struct {
    int client_socket;
    struct sockaddr_in client_addr;
} thread_data_t;

void print_hex(const char *label, const BIGNUM *num) {
    char *hex = BN_bn2hex(num);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

void *handle_client(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    int client_socket = data->client_socket;
    char client_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(data->client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    printf("Client connected from %s:%d\n", client_ip, ntohs(data->client_addr.sin_port));
    
    // 生成DH参数(应与客户端使用相同参数)
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BN_hex2bn(&p, "e6f03f6f711b0c24ff7afe3605a17ab3a11d3e075483aa211958d903f2b41b4b6a6ea1c19bf3144b28ae2575fabe896b1c72b3775a81b3f341ab1ec1adf34f2b"); // 示例使用小素数
    BN_set_word(g, 2);  // 使用2作为生成元

    
    // 初始化DH会话（添加详细检查）
    DHSession session;
    memset(&session, 0, sizeof(DHSession)); // 显式初始化
    
    if (dh_session_init(&session, p, g) != 0) {
        fprintf(stderr, "DH session init failed. Cleaning up...\n");
        BN_free(p);
        BN_free(g);
        close(client_socket);
        free(data);
        return NULL;
    }

    // 打印前验证指针
    if (!session.public_key) {
        fprintf(stderr, "Critical: public_key is NULL after init!\n");
        dh_session_clear(&session);
        BN_free(p);
        BN_free(g);
        close(client_socket);
        free(data);
        return NULL;
    }
    
    print_hex("Server private key", session.private_key);
    print_hex("Server public key", session.public_key);
    
    // 接收客户端公钥
    char buffer[BUFFER_SIZE];
    int len = recv(client_socket, buffer, sizeof(buffer), 0);
    if (len <= 0) {
        perror("Receive failed");
        dh_session_clear(&session);
        close(client_socket);
        free(data);
        return NULL;
    }
    
    BIGNUM *client_pubkey = BN_new();
    if (dh_deserialize_key(buffer, len, client_pubkey) != 0) {
        fprintf(stderr, "Failed to deserialize client public key\n");
        BN_free(client_pubkey);
        dh_session_clear(&session);
        close(client_socket);
        free(data);
        return NULL;
    }
    
    print_hex("Received client public key", client_pubkey);
    
    // 发送服务器公钥
    len = dh_serialize_key(session.public_key, buffer, sizeof(buffer));
    if (send(client_socket, buffer, len, 0) != len) {
        perror("Send failed");
        BN_free(client_pubkey);
        dh_session_clear(&session);
        close(client_socket);
        free(data);
        return NULL;
    }
    
    printf("Sent public key to client\n");
    
    // 计算共享密钥
    if (dh_compute_shared_secret(&session, client_pubkey) != 0) {
        fprintf(stderr, "Failed to compute shared secret\n");
        BN_free(client_pubkey);
        dh_session_clear(&session);
        close(client_socket);
        free(data);
        return NULL;
    }
    
    print_hex("Shared secret", session.shared_secret);
    
    // 清理
    BN_free(client_pubkey);
    BN_free(p);
    BN_free(g);
    dh_session_clear(&session);
    close(client_socket);
    free(data);
    
    printf("Client %s:%d disconnected\n", client_ip, ntohs(data->client_addr.sin_port));
    return NULL;
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // 创建套接字
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }
    
    // 配置服务器地址
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // 绑定套接字
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    // 监听连接
    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server listening on port %d...\n", PORT);
    
    while (1) {
        // 接受新连接
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        // 为每个客户端创建线程
        pthread_t thread_id;
        thread_data_t *data = malloc(sizeof(thread_data_t));
        if (!data) {
            perror("Memory allocation failed");
            close(client_socket);
            continue;
        }
        
        data->client_socket = client_socket;
        memcpy(&data->client_addr, &client_addr, sizeof(client_addr));
        
        if (pthread_create(&thread_id, NULL, handle_client, data) != 0) {
            perror("Thread creation failed");
            free(data);
            close(client_socket);
            continue;
        }
        
        // 分离线程，使其结束后自动释放资源
        pthread_detach(thread_id);
    }
    
    close(server_socket);
    return 0;
}