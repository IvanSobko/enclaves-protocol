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

const char *fifo_pipe = "/tmp/enclave_pipe";

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


bool check_status(sgx_status_t sgx, sgx_status_t enclv, const char *msg) {
    if (sgx == SGX_SUCCESS && enclv == SGX_SUCCESS) {
        printf("From App: %s OK.\n", msg);
        return true;
    } else {
        print_error_message(sgx);
        print_error_message(enclv);

        printf("From App: %s FAILED.\n", msg);
        sgx_destroy_enclave(global_eid);
        return false;
    }
}

//https://www.geeksforgeeks.org/named-pipe-fifo-example-c-program/
void read_from_pipe(void *buf, size_t count)
{
    int fd = open(fifo_pipe, O_RDONLY);
    read(fd, buf, count);
    close(fd);
}

void write_to_pipe(const void *buf, size_t count)
{
    int fd = open(fifo_pipe, O_WRONLY);
    write(fd, buf, count);
    close(fd);
}


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

    sgx_status_t sgx_status;

    sgx_ec256_public_t public_key;
    sgx_status_t enclv_status = create_key_pair(global_eid, &sgx_status, &public_key);
    if (!check_status(sgx_status, enclv_status, "Public key creation")) {
        return -1;
    }

    mkfifo(fifo_pipe, 0666);

    write_to_pipe(&public_key, SGX_ECP256_KEY_SIZE * 2);
    printf("From App: Sent public key to B.\n");


    sgx_ec256_public_t public_key_B;
    read_from_pipe(&public_key_B, SGX_ECP256_KEY_SIZE * 2)
    printf("From App: Read public key of B.\n");


    enclv_status = compute_shared_dhkey(global_eid, &sgx_status, &public_key_B);
    if (!check_status(sgx_status, enclv_status, "Shared key computation")) {
        return -1;
    }

    uint8_t msg[11];
    enclv_status = encrypt_message_psk(global_eid, &sgx_status, msg);
    if (!check_status(sgx_status, enclv_status, "Message encryption")) {
        return -1;
    }
    write_to_pipe(&msg, sizeof(msg));


    uint8_t encrypted_msg[11];
    read_from_pipe(&encrypted_msg, sizeof(encrypted_msg));
    enclv_status = decrypt_and_check_message_psk(global_eid, &sgx_status, encrypted_msg);
    if (!check_status(sgx_status, enclv_status, "Message decryption")) {
        return -1;
    }

    uint8_t challenge[2];
    enclv_status = get_challenge(global_eid, &sgx_status, challenge);
    if (!check_status(sgx_status, enclv_status, "Challenge generation")) {
        return -1;
    }
    write_to_pipe(&challenge, sizeof(challenge));

    uint8_t challenge_result[3];
    read_from_pipe(&challenge_result, sizeof(challenge_result));
    enclv_status = check_challenge_result(global_eid, &sgx_status, challenge_result);
    if (!check_status(sgx_status, enclv_status, "Challenge result")) {
        return -1;
    }

    sgx_destroy_enclave(global_eid);
    printf("From App: Enclave destroyed.\n");
    return 0;
}
