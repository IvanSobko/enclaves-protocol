#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

#define SGX_ECP256_KEY_SIZE 32

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
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
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if (ret == sgx_errlist[idx].err) {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

bool check_status(sgx_status_t sgx, sgx_status_t enclv) {
    if (sgx == SGX_SUCCESS && enclv == SGX_SUCCESS) {
        return true;
    } else {
        print_error_message(sgx);
        print_error_message(enclv);
        return false;
    }
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    /* Initialize the enclave */
    if (initialize_enclave() < 0) {
        printf("Enclave initialization failed.\n");
        return -1;
    }
    printf("From App: Enclave creation success. \n");
    printf("From App: Write your protocol here ... \n");


    sgx_status_t sgx_status;

    sgx_ec256_public_t public_key;
    sgx_status_t enclv_status = create_key_pair(global_eid, &sgx_status, &public_key);
    if (check_status(sgx_status, enclv_status)) {
        printf("Public key creation OK.\n");
    } else {
        printf("Public key creation FAILED.\n");
        return -1;
    }


    //https://www.geeksforgeeks.org/named-pipe-fifo-example-c-program/
    const char *fifo_pipe = "/tmp/enclave_pipe";
    mkfifo(fifo_pipe, 0666);

    int fd = open(fifo_pipe, O_RDONLY);

    sgx_ec256_public_t public_key_A;
    read(fd, public_key_A.gx, SGX_ECP256_KEY_SIZE);
    read(fd, public_key_A.gy, SGX_ECP256_KEY_SIZE);

    close(fd);
    printf("Read public key of A.\n");


    fd = open(fifo_pipe, O_WRONLY);

    write(fd, public_key.gx, SGX_ECP256_KEY_SIZE);
    write(fd, public_key.gy, SGX_ECP256_KEY_SIZE);

    close(fd);
    printf("Sent public key to A.\n");


    enclv_status = compute_shared_dhkey(global_eid, &sgx_status, &public_key_A);
    if (check_status(sgx_status, enclv_status)) {
        printf("Shared key computation OK.\n");
    } else {
        printf("Shared key computation FAILED.\n");
        return -1;
    }

    fd = open(fifo_pipe, O_RDONLY);
    uint8_t encrypted_msg[11];
    read(fd, &encrypted_msg, sizeof(encrypted_msg));
    close(fd);
    enclv_status = decrypt_and_check_message_psk(global_eid, &sgx_status, encrypted_msg);
    if (check_status(sgx_status, enclv_status)) {
        printf("Message decryption OK.\n");
    } else {
        printf("Error: Message decryption FAILED.\n");
        return -1;
    }


    uint8_t msg[11];
    enclv_status = encrypt_message_psk(global_eid, &sgx_status, msg);
    if (check_status(sgx_status, enclv_status)) {
        printf("Message encryption OK.\n");
    } else {
        printf("Error: Message encryption FAILED.\n");
        return -1;
    }

    fd = open(fifo_pipe, O_WRONLY);
    write(fd, &msg, sizeof(msg));
    close(fd);




    fd = open(fifo_pipe, O_RDONLY);
    uint8_t challenge[2];
    read(fd, &challenge, sizeof(challenge));
    close(fd);

    enclv_status = receive_challenge(global_eid, &sgx_status, challenge);
    if (check_status(sgx_status, enclv_status)) {
        printf("Challenge receive OK.\n");
    } else {
        printf("Error: Challenge receive FAILED.\n");
        return -1;
    }




    uint8_t response[3];
    enclv_status = complete_and_send_challenge(global_eid, &sgx_status, response);
    if (check_status(sgx_status, enclv_status)) {
        printf("Challenge compute and send OK.\n");
    } else {
        printf("Error: Challenge compute and send FAILED.\n");
        return -1;
    }

    fd = open(fifo_pipe, O_WRONLY);
    write(fd, &response, sizeof(response));
    close(fd);


    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("From App: Enclave destroyed.\n");
    return 0;
}

