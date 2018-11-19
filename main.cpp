/*
 * Copyright (c) 2018, Arm Limited and affiliates
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "psa/crypto.h"
#include <string.h>
#include <inttypes.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif

#define ASSERT_STATUS(actual, expected)                                       \
    do                                                                        \
    {                                                                         \
        if((actual) != (expected))                                            \
        {                                                                     \
            mbedtls_printf( "\tassertion failed at %s:%d - "                  \
                            "actual:%" PRId32 "expected:%" PRId32 "\n",     \
                            __FILE__, __LINE__,                               \
                            (psa_status_t) actual, (psa_status_t) expected ); \
            goto exit;                                                        \
        }                                                                     \
    } while (0)

#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_AES_C) || \
    !defined(MBEDTLS_CIPHER_MODE_CBC) || !defined(MBEDTLS_CIPHER_MODE_CTR) || \
    !defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
int main(void)
{
    mbedtls_printf("Not all of the required options are defined:\n"
                   "  - MBEDTLS_PSA_CRYPTO_C\n"
                   "  - MBEDTLS_AES_C\n"
                   "  - MBEDTLS_CIPHER_MODE_CBC\n"
                   "  - MBEDTLS_CIPHER_MODE_CTR\n"
                   "  - MBEDTLS_CIPHER_MODE_WITH_PADDING\n");
    return 0;
}
#else

/* Use key slot 1 for our cipher key. Key slot 0 is reserved as unused. */
static const psa_key_slot_t key_slot_cipher = 1;

static psa_status_t set_key_policy(psa_key_slot_t key_slot,
                                   psa_key_usage_t key_usage,
                                   psa_algorithm_t alg)
{
    psa_status_t status;
    psa_key_policy_t policy;

    psa_key_policy_init(&policy);
    psa_key_policy_set_usage(&policy, key_usage, alg);
    status = psa_set_key_policy(key_slot, &policy);
    ASSERT_STATUS(status, PSA_SUCCESS);
exit:
    return status;
}

static psa_status_t cipher_operation(psa_cipher_operation_t *operation,
                                     const uint8_t *input,
                                     size_t input_size,
                                     size_t part_size,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_len)
{
    psa_status_t status;
    size_t bytes_to_write = 0, bytes_written = 0, len = 0;

    *output_len = 0;
    while (bytes_written != input_size) {
        bytes_to_write = (input_size - bytes_written > part_size ?
                          part_size :
                          input_size - bytes_written);

        status = psa_cipher_update(operation, input + bytes_written,
                                   bytes_to_write, output + *output_len,
                                   output_size - *output_len, &len);
        ASSERT_STATUS(status, PSA_SUCCESS);

        bytes_written += bytes_to_write;
        *output_len += len;
    }

    status = psa_cipher_finish(operation, output + *output_len,
                               output_size - *output_len, &len);
    ASSERT_STATUS(status, PSA_SUCCESS);
    *output_len += len;

exit:
    return status;
}

static psa_status_t cipher_encrypt(psa_key_slot_t key_slot,
                                   psa_algorithm_t alg,
                                   uint8_t *iv,
                                   size_t iv_size,
                                   const uint8_t *input,
                                   size_t input_size,
                                   size_t part_size,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_len)
{
    psa_status_t status;
    psa_cipher_operation_t operation;
    size_t iv_len = 0;

    memset(&operation, 0, sizeof(operation));
    status = psa_cipher_encrypt_setup(&operation, key_slot, alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_cipher_generate_iv(&operation, iv, iv_size, &iv_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_operation(&operation, input, input_size, part_size,
                              output, output_size, output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    psa_cipher_abort(&operation);
    return status;
}

static psa_status_t cipher_decrypt(psa_key_slot_t key_slot,
                                   psa_algorithm_t alg,
                                   const uint8_t *iv,
                                   size_t iv_size,
                                   const uint8_t *input,
                                   size_t input_size,
                                   size_t part_size,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_len)
{
    psa_status_t status;
    psa_cipher_operation_t operation;

    memset(&operation, 0, sizeof(operation));
    status = psa_cipher_decrypt_setup(&operation, key_slot, alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_cipher_set_iv(&operation, iv, iv_size);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_operation(&operation, input, input_size, part_size,
                              output, output_size, output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    psa_cipher_abort(&operation);
    return status;
}

static psa_status_t cipher_example_encrypt_decrypt_aes_cbc_nopad_1_block(void)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE(PSA_KEY_TYPE_AES),
        key_bits = 256,
        part_size = block_size,
    };
    const psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;

    psa_status_t status;
    size_t output_len = 0;
    uint8_t iv[block_size];
    uint8_t input[block_size];
    uint8_t encrypt[block_size];
    uint8_t decrypt[block_size];

    status = psa_generate_random(input, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = set_key_policy(key_slot_cipher,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT,
                            alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_generate_key(key_slot_cipher, PSA_KEY_TYPE_AES, key_bits,
                              NULL, 0);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_encrypt(key_slot_cipher, alg, iv, sizeof(iv),
                            input, sizeof(input), part_size,
                            encrypt, sizeof(encrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_decrypt(key_slot_cipher, alg, iv, sizeof(iv),
                            encrypt, output_len, part_size,
                            decrypt, sizeof(decrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = memcmp(input, decrypt, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    psa_destroy_key(key_slot_cipher);
    return status;
}

static psa_status_t cipher_example_encrypt_decrypt_aes_cbc_pkcs7_multi(void)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE(PSA_KEY_TYPE_AES),
        key_bits = 256,
        input_size = 100,
        part_size = 10,
    };

    const psa_algorithm_t alg = PSA_ALG_CBC_PKCS7;

    psa_status_t status;
    size_t output_len = 0;
    uint8_t iv[block_size], input[input_size],
            encrypt[input_size + block_size], decrypt[input_size + block_size];

    status = psa_generate_random(input, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = set_key_policy(key_slot_cipher,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT,
                            alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_generate_key(key_slot_cipher, PSA_KEY_TYPE_AES, key_bits,
                              NULL, 0);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_encrypt(key_slot_cipher, alg, iv, sizeof(iv),
                            input, sizeof(input), part_size,
                            encrypt, sizeof(encrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_decrypt(key_slot_cipher, alg, iv, sizeof(iv),
                            encrypt, output_len, part_size,
                            decrypt, sizeof(decrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = memcmp(input, decrypt, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    psa_destroy_key(key_slot_cipher);
    return status;
}

static psa_status_t cipher_example_encrypt_decrypt_aes_ctr_multi(void)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE(PSA_KEY_TYPE_AES),
        key_bits = 256,
        input_size = 100,
        part_size = 10,
    };
    const psa_algorithm_t alg = PSA_ALG_CTR;

    psa_status_t status;
    size_t output_len = 0;
    uint8_t iv[block_size], input[input_size], encrypt[input_size],
            decrypt[input_size];

    status = psa_generate_random(input, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = set_key_policy(key_slot_cipher,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT,
                            alg);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_generate_key(key_slot_cipher, PSA_KEY_TYPE_AES, key_bits,
                              NULL, 0);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_encrypt(key_slot_cipher, alg, iv, sizeof(iv),
                            input, sizeof(input), part_size,
                            encrypt, sizeof(encrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = cipher_decrypt(key_slot_cipher, alg, iv, sizeof(iv),
                            encrypt, output_len, part_size,
                            decrypt, sizeof(decrypt), &output_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = memcmp(input, decrypt, sizeof(input));
    ASSERT_STATUS(status, PSA_SUCCESS);

exit:
    psa_destroy_key(key_slot_cipher);
    return status;
}

static void cipher_examples(void)
{
    psa_status_t status;

    mbedtls_printf("cipher encrypt/decrypt AES CBC no padding:\n");
    status = cipher_example_encrypt_decrypt_aes_cbc_nopad_1_block();
    if (status == PSA_SUCCESS) {
        mbedtls_printf("\tsuccess!\n");
    }

    mbedtls_printf("cipher encrypt/decrypt AES CBC PKCS7 multipart:\n");
    status = cipher_example_encrypt_decrypt_aes_cbc_pkcs7_multi();
    if (status == PSA_SUCCESS) {
        mbedtls_printf("\tsuccess!\n");
    }

    mbedtls_printf("cipher encrypt/decrypt AES CTR multipart:\n");
    status = cipher_example_encrypt_decrypt_aes_ctr_multi();
    if (status == PSA_SUCCESS) {
        mbedtls_printf("\tsuccess!\n");
    }
}

int main(void)
{
    ASSERT_STATUS(psa_crypto_init(), PSA_SUCCESS);
    cipher_examples();
exit:
    mbedtls_psa_crypto_free();
    return 0;
}
#endif /* MBEDTLS_PSA_CRYPTO_C && MBEDTLS_AES_C && MBEDTLS_CIPHER_MODE_CBC &&
          MBEDTLS_CIPHER_MODE_CTR && MBEDTLS_CIPHER_MODE_WITH_PADDING */
