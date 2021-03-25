/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <termios.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "error_codes.h"

#define BUF_LEN 1024
#define MAX_LISTEN_FD 64
#define PASS_MAX 32
#define MAX_ENC_KEY_LEN 4096
#define ENC_KEY_FILE_NAME "enc_file"
#define ENCLAVE_FILENAME "enclave.signed.so"

sgx_enclave_id_t global_eid = 0;

int set_echo_mode(int fd, int option)
{
    struct termios term;
    if (tcgetattr(fd, &term) != 0) {
        return CC_FAIL;
    }
    if (option) {
        term.c_lflag |= (ECHO | ECHOE | ECHOK | ECHONL);
    } else {
        term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    }
    if (tcsetattr(fd, TCSAFLUSH, &term) != 0) {
        return CC_FAIL;
    }
    return CC_SUCCESS;
}

int get_password_and_seal_key(sgx_enclave_id_t global_eid, const char *key_file_name, const char *enc_key_file_name)
{
    int res = CC_FAIL;
    int sgx_res = SGX_ERROR_UNEXPECTED;
    size_t retval = 0;
    size_t pw_len = 0;
    char password[PASS_MAX] = {0};
    char *enc_key = NULL;
    FILE *fp = NULL;

    printf("Please input password:\n");
    if (set_echo_mode(STDIN_FILENO, 0)) {
        return CC_FAIL;
    }
    if (fgets((char *)password, PASS_MAX, stdin) == NULL) {
        return CC_FAIL;
    }
    pw_len = strlen((const char *)password);
    if (password[pw_len - 1] == '\n') {
        password[pw_len - 1] = 0;
        pw_len--;
    }
    if (set_echo_mode(STDIN_FILENO, 1)) {
        goto end;
    }
    enc_key = malloc(MAX_ENC_KEY_LEN);
    if (enc_key == NULL) {
        goto end;
    }
    sgx_res = seal_key(global_eid, &retval, key_file_name, strlen(key_file_name) + 1, password, pw_len + 1, 
                   enc_key, MAX_ENC_KEY_LEN);
    if (sgx_res != SGX_SUCCESS || retval == 0) {
        goto end;
    }
    fp = fopen(enc_key_file_name, "w+");
    if (fp == NULL) {
        goto end;
    }
    if (fwrite(enc_key, sizeof(char), retval, fp) != retval) {
        fclose(fp);
        goto end;
    }
    fclose(fp);
    if (remove(key_file_name) == 0) {
        printf("delete origin key file success!\n");
    } else {
        printf("delete origin key file error!\n");
        goto end;
    }

    res = CC_SUCCESS;
end:
    memset(password, 0, pw_len);
    return res;
}

int start_server(int port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons((uint16_t)port);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        return -1;
    }
    listen(server_fd, MAX_LISTEN_FD);
    return server_fd;
}

int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
          
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        return -1; 
    }   

    return 0;
}

int main(int argc, const char *argv[])
{
    struct sockaddr_in client_addr;
    socklen_t client_len;
    int server_fd = -1;
    int tlsc_fd = -1;
    int retval = 0;
    sgx_status_t res = SGX_ERROR_UNEXPECTED;

    if (argc != 4) {
        printf("usage: %s port cert_file key_file\n", argv[0]);
        return res;
    }

    server_fd = start_server(atoi(argv[1]));
    if (server_fd < 0) {
        return res;
    } 
    tlsc_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (tlsc_fd < 0) {
        return res;
    }
    printf("Create enclave\n");
    if (initialize_enclave() < 0) {
        printf("Create enclave error\n");
        goto end;
    }
    res = get_password_and_seal_key(global_eid, argv[3], ENC_KEY_FILE_NAME);
    if (res !=  CC_SUCCESS) {
        printf("get_password_and_seal_key error\n");
        goto end;
    }
    res = start_enclave_tls(global_eid, &retval, tlsc_fd, argv[2], strlen(argv[2]) + 1, ENC_KEY_FILE_NAME, 
                            strlen(ENC_KEY_FILE_NAME) + 1);
    if (res !=  SGX_SUCCESS || retval !=  CC_SUCCESS) {
        printf("start_enclave_tls error\n");			        
        goto end;
    }

    printf("enclve tls finish\n");

end:
    sgx_destroy_enclave(global_eid);
    close(tlsc_fd);
    close(server_fd);
    return res;
}
