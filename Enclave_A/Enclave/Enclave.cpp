#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

int enclave_secret = 1337;

sgx_ecc_state_handle_t encl_ecc_param;
sgx_ec256_private_t encl_priv_key;
sgx_ec256_dh_shared_t encl_shared_key;
sgx_aes_ctr_128bit_key_t encl_secret_key;

uint8_t challenge_a = 0;
uint8_t challenge_b = 0;

uint8_t IV[16] = {0};

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

//https://github.com/intel/linux-sgx/blob/master/sdk/tkey_exchange/tkey_exchange.cpp
sgx_status_t create_key_pair(sgx_ec256_public_t *public_key)
{

    sgx_status_t status = sgx_ecc256_open_context(&encl_ecc_param);
    if (status != SGX_SUCCESS) {
        return status;
    }

    sgx_ec256_public_t encl_pub_key;
    status = sgx_ecc256_create_key_pair(&encl_priv_key, &encl_pub_key, encl_ecc_param);
    if (status != SGX_SUCCESS) {
        return status;
    }

    memcpy(public_key, &encl_pub_key, sizeof(sgx_ec256_public_t));

    return SGX_SUCCESS;
}

sgx_status_t compute_shared_dhkey(sgx_ec256_public_t *public_key)
{

    sgx_status_t status = sgx_ecc256_compute_shared_dhkey(&encl_priv_key, public_key, &encl_shared_key, encl_ecc_param);
    if (status != SGX_SUCCESS) {
        return status;
    }

    //encl_shared_key is 256 bit, sgx_aes_ctr_encrypt accepts only 128 bit key, so we use the first 128 bits from the 256 bit shared key
    for (uint32_t j = 0; j < sizeof(sgx_aes_ctr_128bit_key_t); j++) {
        encl_secret_key[j] = encl_shared_key.s[j];
    }

    return SGX_SUCCESS;
}

sgx_status_t encrypt_message_psk(uint8_t* result)
{
    char PSK_A[] = "I AM ALICE";
    uint32_t length = sizeof(PSK_A);
    sgx_status_t status = sgx_aes_ctr_encrypt(&encl_secret_key, (uint8_t *)PSK_A, length, IV, 1, result);
    return status;
}

sgx_status_t decrypt_and_check_message_psk(uint8_t* encrypted_msg)
{

    char PSK_B[] = "I AM BOBOB";
    uint32_t length = sizeof(PSK_B);
    uint8_t decrypted_message[length];
    sgx_status_t status = sgx_aes_ctr_decrypt(&encl_secret_key, encrypted_msg, length, IV, 1, decrypted_message);
    if (status != SGX_SUCCESS) {
        return status;
    }

    if (strcmp((char *)decrypted_message, PSK_B) != 0) {
        status = SGX_ERROR_INVALID_PARAMETER;
    }

    printf("From Enclave A: received message is: %s.\n", (char *)decrypted_message);
    return status;
}

sgx_status_t get_challenge(uint8_t *result)
{
    sgx_read_rand(&challenge_a, 1);
    sgx_read_rand(&challenge_b, 1);

    printf("Generated challenge: %i, %i.\n", challenge_a, challenge_b);

    uint8_t buff[2];
    uint8_t *ptr = (uint8_t*) &buff;

    memcpy(ptr, &challenge_a, 1);
    ptr++;
    memcpy(ptr, &challenge_b, 1);

    sgx_status_t status = sgx_aes_ctr_encrypt(&encl_secret_key, buff, sizeof(buff), IV, 1, result);
    return status;
}

sgx_status_t check_challenge_result(uint8_t *result)
{
    uint8_t buff[3];
    sgx_status_t status = sgx_aes_ctr_decrypt(&encl_secret_key, result, sizeof(buff), IV, 1, (uint8_t *)buff);

    int expected_value = (int)challenge_a + (int)challenge_b;
    int actual_value = *(int *)buff;

    if (expected_value != actual_value) {
        printf("From Enclave A: numbers dont match: %i vs %i.\n", expected_value, actual_value);
        status = SGX_ERROR_INVALID_PARAMETER;
    }
    return status;
}


sgx_status_t printSecret()
{
    char buf[BUFSIZ] = {"From Enclave: Hello from the enclave.\n"};
    ocall_print_string(buf);
    printf("From Enclave: Another way to print from the Enclave. My secret is %u.\n", enclave_secret);
    return SGX_SUCCESS;
}
