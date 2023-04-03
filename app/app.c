// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX
#include "sgx_urts.h"
#include "app.h"
#include "Enclave_u.h"

sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; 
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

int initialize_enclave(void)
{
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}


void send_email_with_python(const char* to, const char* subject, const char* body) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "python3 /root/sgx/samplecode/file/app/send_email.py \"%s\" \"%s\" \"%s\"", to, subject, body);
    system(cmd);
}

int generate_otp() {
    srand(time(0));
    return 100000 + rand() % 900000; // Generates a random 6-digit number
}

void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    sgx_status_t sgx_ret = SGX_SUCCESS;

    int ret = 0;

    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    char email[256];
    size_t max_buf_len = sizeof(email);

    int retval;
    sgx_ret = ecall_pass_string(global_eid, &retval, email, max_buf_len);

    if (sgx_ret != SGX_SUCCESS) {
        printf("[FAIL] Failed to get string from enclave.\n");
        return 1;
    } else if (retval == 99) {
        printf("[FAIL] Wrong email id or password, quitting application...\n");
        sgx_destroy_enclave(global_eid);
        return 1;
    }

    email[strcspn(email, "\n")] = 0; // Remove trailing newline character

    int otp = generate_otp();
    char otp_str[10];
    snprintf(otp_str, sizeof(otp_str), "%d", otp);

    const char* recipient = email;
    const char* subject = "One-Time Password for your wallet!";
    char body[256];
    snprintf(body, sizeof(body), "Your one-time password (OTP) is: %s", otp_str);

    printf("[OK] Sending OTP to your email, please wait...\n");
    send_email_with_python(recipient, subject, body);

// --------------------------- OTP ----------------------------------

    printf("[+] Enter the OTP you received in your email: ");
    int entered_otp;
    scanf("%d", &entered_otp);
    clear_input_buffer();

    if (otp != entered_otp) {
        printf("[FAIL] Incorrect OTP. Terminating the program.\n");
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    printf("[OK] OTP is correct. You may proceed.\n");

// ------------------------------------------------------------------
    bool keep_running = true;

    while (keep_running) {
        char user_input[256];

        printf("[INFO] Enter a command (type 'help' for assistance): ");
        fgets(user_input, sizeof(user_input), stdin);
        user_input[strcspn(user_input, "\n")] = 0;

        if (strcmp(user_input, "exit") == 0) {
            keep_running = false;
        } else if (strcmp(user_input, "write") == 0) {
            sgx_ret = write_file(global_eid, &ret);
            if(sgx_ret != SGX_SUCCESS) {
                print_error_message(sgx_ret);
            } else {
                printf("[OK] Write file success ...\n");
            }
        } else if (strcmp(user_input, "read") == 0) {
            sgx_ret = read_file(global_eid, &ret);
            if(sgx_ret != SGX_SUCCESS) {
                print_error_message(sgx_ret);
            } else {
                // printf("read_file success ...\n");
            }
        } else if (strcmp(user_input, "find") == 0) {
            sgx_ret = find_by_key(global_eid, &ret);
            if(sgx_ret != SGX_SUCCESS) {
                print_error_message(sgx_ret);
            }
        } else if (strcmp(user_input, "add") == 0) {
            sgx_ret = add_data(global_eid, &ret);
            if(sgx_ret != SGX_SUCCESS) {
                print_error_message(sgx_ret);
            }
        } else if (strcmp(user_input, "clear") == 0) {
            sgx_ret = delete_file(global_eid, &ret);
            if(sgx_ret != SGX_SUCCESS) {
                print_error_message(sgx_ret);
            }
        } else if (strcmp(user_input, "remove") == 0) {
            sgx_ret = delete_data(global_eid, &ret);
            if(sgx_ret != SGX_SUCCESS) {
                print_error_message(sgx_ret);
            }
        } else if (strcmp(user_input, "reset") == 0) {
            sgx_ret = change_password(global_eid, &ret);
            if(sgx_ret != SGX_SUCCESS) {
                print_error_message(sgx_ret);
            }
        } else if (strcmp(user_input, "recommend") == 0) {
            sgx_ret = recommend_password(global_eid, &ret);
            if(sgx_ret != SGX_SUCCESS) {
                print_error_message(sgx_ret);
            }
        } else if (strcmp(user_input, "help") == 0) {
            printf("[+] Enter 'write' to create and write data to the wallet! \n");
            printf("[+] Enter 'read' to read data from the wallet! \n");
            printf("[+] Enter 'find' to find data from the wallet! \n");
            printf("[+] Enter 'add' to add data to the wallet! \n");
            printf("[+] Enter 'remove' to remove data to the wallet! \n");
            printf("[+] Enter 'clear' to clear entire data from the wallet! \n");
            printf("[+] Enter 'reset' to reset your master password! \n");
            printf("[+] Enter 'recommend' to recommend your master password! \n");
            printf("[+] Enter 'exit' to quit! \n");
        }
        else {
            printf("[ERROR] Invalid command, please try again.\n");
        }
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}
