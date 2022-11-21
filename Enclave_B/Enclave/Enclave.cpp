#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>


int enclave_secret = 42;

sgx_ecc_state_handle_t enclv_ecc_param;
sgx_ec256_public_t enclv_pub_key;
sgx_ec256_private_t enclv_priv_key;
sgx_ec256_dh_shared_t enclv_shared_key;
sgx_aes_ctr_128bit_key_t enclv_secret_key;

uint8_t IV[16] = {0};
uint8_t challenge[2];

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
    sgx_status_t status = sgx_ecc256_open_context(&enclv_ecc_param);
    if (status != SGX_SUCCESS) {
        return status;
    }

    status = sgx_ecc256_create_key_pair(&enclv_priv_key, &enclv_pub_key, enclv_ecc_param);
    if (status != SGX_SUCCESS) {
        return status;
    }

    memcpy(public_key, &enclv_pub_key, sizeof(sgx_ec256_public_t));

    return status;
}

sgx_status_t compute_shared_dhkey(sgx_ec256_public_t *public_key)
{

    sgx_status_t status = sgx_ecc256_compute_shared_dhkey(&enclv_priv_key, public_key, &enclv_shared_key, enclv_ecc_param);
    if (status != SGX_SUCCESS) {
        return status;
    }

    //enclv_shared_key is 256 bit, sgx_aes_ctr_encrypt accepts only 128 bit key, so we use the first 128 bits from the 256 bit shared key
    for (uint32_t j = 0; j < sizeof(sgx_aes_ctr_128bit_key_t); j++) {
        enclv_secret_key[j] = enclv_shared_key.s[j];
    }

    return status;
}

sgx_status_t encrypt_message_psk(uint8_t* result)
{
    char PSK_B[] = "I AM BOBOB";
    uint32_t length = sizeof(PSK_B);
    uint8_t *psk_allocated = (uint8_t *)malloc(length);
    memcpy(psk_allocated, PSK_B, length);

    sgx_status_t status = sgx_aes_ctr_encrypt(&enclv_secret_key, psk_allocated, length, IV, 1, result);
    free(psk_allocated);
    return status;
}

sgx_status_t decrypt_and_check_message_psk(uint8_t* encrypted_msg)
{
    char PSK_A[] = "I AM ALICE";
    uint32_t length = sizeof(PSK_A);
    uint8_t *decrypted_message = (uint8_t *)malloc(length);
    sgx_status_t status = sgx_aes_ctr_decrypt(&enclv_secret_key, encrypted_msg, length, IV, 1, decrypted_message);
    if (status != SGX_SUCCESS) {
        return status;
    }

    if (strcmp((char *)decrypted_message, PSK_A) != 0) {
        status = SGX_ERROR_INVALID_PARAMETER;
    }

    printf("From Enclave B: received message is: %s.\n", (char *)decrypted_message);
    free(decrypted_message);
    return status;
}

sgx_status_t receive_challenge(uint8_t *encrypted_challenge)
{
    return sgx_aes_ctr_decrypt(&enclv_secret_key, encrypted_challenge, 2, IV, 1, challenge);;
}

sgx_status_t complete_and_send_challenge(/*uint8_t *response*/)
{
    printf("Challenge: %i, %i.\n", challenge[0], challenge[1]);
    return SGX_SUCCESS;
}

sgx_status_t printSecret()
{
    char buf[BUFSIZ] = {"From Enclave: Hello from the enclave.\n"};
    ocall_print_string(buf);
    printf("From Enclave: Another way to print from the Enclave. My secret is %u.\n", enclave_secret);
    return SGX_SUCCESS;
}
