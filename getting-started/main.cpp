/*
 * Copyright (c) 2018-2019, Arm Limited and affiliates
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
#include <mbed.h>
#include <platform.h>
#include "psa/crypto.h"
#include "mbedtls/version.h"
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define SOME_PLAINTEXT "I am plaintext."
#define SOME_CIPHERTEXT \
{ \
0x9f, 0xbf, 0x0b, 0x99, 0x70, 0xe0, 0x3d, 0xab, \
0xf7, 0x65, 0x43, 0x88, 0x09, 0x2c, 0xb4, 0x66, \
}
#define ENCRYPTED_WITH_IV \
{ \
0x0e, 0x42, 0x75, 0x78, 0xb5, 0x0d, 0x17, 0x4f, \
0x6e, 0x13, 0xf4, 0xfd, 0x16, 0x30, 0x3e, 0xc7, \
}
/* This key is present as a global define for the purpose of example. In
 * real-world applications, you would not have a key hardcoded in source like
 * this. */
static const uint8_t AES_KEY[] =
{
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
};
/* This key is present as a global define for the purpose of example. In
 * real-world applications, you would not have a key hardcoded in source like
 * this. */
static const uint8_t RSA_KEY[] =
{
    0x30, 0x82, 0x02, 0x5e, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xaf,
    0x05, 0x7d, 0x39, 0x6e, 0xe8, 0x4f, 0xb7, 0x5f, 0xdb, 0xb5, 0xc2, 0xb1,
    0x3c, 0x7f, 0xe5, 0xa6, 0x54, 0xaa, 0x8a, 0xa2, 0x47, 0x0b, 0x54, 0x1e,
    0xe1, 0xfe, 0xb0, 0xb1, 0x2d, 0x25, 0xc7, 0x97, 0x11, 0x53, 0x12, 0x49,
    0xe1, 0x12, 0x96, 0x28, 0x04, 0x2d, 0xbb, 0xb6, 0xc1, 0x20, 0xd1, 0x44,
    0x35, 0x24, 0xef, 0x4c, 0x0e, 0x6e, 0x1d, 0x89, 0x56, 0xee, 0xb2, 0x07,
    0x7a, 0xf1, 0x23, 0x49, 0xdd, 0xee, 0xe5, 0x44, 0x83, 0xbc, 0x06, 0xc2,
    0xc6, 0x19, 0x48, 0xcd, 0x02, 0xb2, 0x02, 0xe7, 0x96, 0xae, 0xbd, 0x94,
    0xd3, 0xa7, 0xcb, 0xf8, 0x59, 0xc2, 0xc1, 0x81, 0x9c, 0x32, 0x4c, 0xb8,
    0x2b, 0x9c, 0xd3, 0x4e, 0xde, 0x26, 0x3a, 0x2a, 0xbf, 0xfe, 0x47, 0x33,
    0xf0, 0x77, 0x86, 0x9e, 0x86, 0x60, 0xf7, 0xd6, 0x83, 0x4d, 0xa5, 0x3d,
    0x69, 0x0e, 0xf7, 0x98, 0x5f, 0x6b, 0xc3, 0x02, 0x03, 0x01, 0x00, 0x01,
    0x02, 0x81, 0x81, 0x00, 0x87, 0x4b, 0xf0, 0xff, 0xc2, 0xf2, 0xa7, 0x1d,
    0x14, 0x67, 0x1d, 0xdd, 0x01, 0x71, 0xc9, 0x54, 0xd7, 0xfd, 0xbf, 0x50,
    0x28, 0x1e, 0x4f, 0x6d, 0x99, 0xea, 0x0e, 0x1e, 0xbc, 0xf8, 0x2f, 0xaa,
    0x58, 0xe7, 0xb5, 0x95, 0xff, 0xb2, 0x93, 0xd1, 0xab, 0xe1, 0x7f, 0x11,
    0x0b, 0x37, 0xc4, 0x8c, 0xc0, 0xf3, 0x6c, 0x37, 0xe8, 0x4d, 0x87, 0x66,
    0x21, 0xd3, 0x27, 0xf6, 0x4b, 0xbe, 0x08, 0x45, 0x7d, 0x3e, 0xc4, 0x09,
    0x8b, 0xa2, 0xfa, 0x0a, 0x31, 0x9f, 0xba, 0x41, 0x1c, 0x28, 0x41, 0xed,
    0x7b, 0xe8, 0x31, 0x96, 0xa8, 0xcd, 0xf9, 0xda, 0xa5, 0xd0, 0x06, 0x94,
    0xbc, 0x33, 0x5f, 0xc4, 0xc3, 0x22, 0x17, 0xfe, 0x04, 0x88, 0xbc, 0xe9,
    0xcb, 0x72, 0x02, 0xe5, 0x94, 0x68, 0xb1, 0xea, 0xd1, 0x19, 0x00, 0x04,
    0x77, 0xdb, 0x2c, 0xa7, 0x97, 0xfa, 0xc1, 0x9e, 0xda, 0x3f, 0x58, 0xc1,
    0x02, 0x41, 0x00, 0xe2, 0xab, 0x76, 0x08, 0x41, 0xbb, 0x9d, 0x30, 0xa8,
    0x1d, 0x22, 0x2d, 0xe1, 0xeb, 0x73, 0x81, 0xd8, 0x22, 0x14, 0x40, 0x7f,
    0x1b, 0x97, 0x5c, 0xbb, 0xfe, 0x4e, 0x1a, 0x94, 0x67, 0xfd, 0x98, 0xad,
    0xbd, 0x78, 0xf6, 0x07, 0x83, 0x6c, 0xa5, 0xbe, 0x19, 0x28, 0xb9, 0xd1,
    0x60, 0xd9, 0x7f, 0xd4, 0x5c, 0x12, 0xd6, 0xb5, 0x2e, 0x2c, 0x98, 0x71,
    0xa1, 0x74, 0xc6, 0x6b, 0x48, 0x81, 0x13, 0x02, 0x41, 0x00, 0xc5, 0xab,
    0x27, 0x60, 0x21, 0x59, 0xae, 0x7d, 0x6f, 0x20, 0xc3, 0xc2, 0xee, 0x85,
    0x1e, 0x46, 0xdc, 0x11, 0x2e, 0x68, 0x9e, 0x28, 0xd5, 0xfc, 0xbb, 0xf9,
    0x90, 0xa9, 0x9e, 0xf8, 0xa9, 0x0b, 0x8b, 0xb4, 0x4f, 0xd3, 0x64, 0x67,
    0xe7, 0xfc, 0x17, 0x89, 0xce, 0xb6, 0x63, 0xab, 0xda, 0x33, 0x86, 0x52,
    0xc3, 0xc7, 0x3f, 0x11, 0x17, 0x74, 0x90, 0x2e, 0x84, 0x05, 0x65, 0x92,
    0x70, 0x91, 0x02, 0x41, 0x00, 0xb6, 0xcd, 0xbd, 0x35, 0x4f, 0x7d, 0xf5,
    0x79, 0xa6, 0x3b, 0x48, 0xb3, 0x64, 0x3e, 0x35, 0x3b, 0x84, 0x89, 0x87,
    0x77, 0xb4, 0x8b, 0x15, 0xf9, 0x4e, 0x0b, 0xfc, 0x05, 0x67, 0xa6, 0xae,
    0x59, 0x11, 0xd5, 0x7a, 0xd6, 0x40, 0x9c, 0xf7, 0x64, 0x7b, 0xf9, 0x62,
    0x64, 0xe9, 0xbd, 0x87, 0xeb, 0x95, 0xe2, 0x63, 0xb7, 0x11, 0x0b, 0x9a,
    0x1f, 0x9f, 0x94, 0xac, 0xce, 0xd0, 0xfa, 0xfa, 0x4d, 0x02, 0x40, 0x71,
    0x19, 0x5e, 0xec, 0x37, 0xe8, 0xd2, 0x57, 0xde, 0xcf, 0xc6, 0x72, 0xb0,
    0x7a, 0xe6, 0x39, 0xf1, 0x0c, 0xbb, 0x9b, 0x0c, 0x73, 0x9d, 0x0c, 0x80,
    0x99, 0x68, 0xd6, 0x44, 0xa9, 0x4e, 0x3f, 0xd6, 0xed, 0x92, 0x87, 0x07,
    0x7a, 0x14, 0x58, 0x3f, 0x37, 0x90, 0x58, 0xf7, 0x6a, 0x8a, 0xec, 0xd4,
    0x3c, 0x62, 0xdc, 0x8c, 0x0f, 0x41, 0x76, 0x66, 0x50, 0xd7, 0x25, 0x27,
    0x5a, 0xc4, 0xa1, 0x02, 0x41, 0x00, 0xbb, 0x32, 0xd1, 0x33, 0xed, 0xc2,
    0xe0, 0x48, 0xd4, 0x63, 0x38, 0x8b, 0x7b, 0xe9, 0xcb, 0x4b, 0xe2, 0x9f,
    0x4b, 0x62, 0x50, 0xbe, 0x60, 0x3e, 0x70, 0xe3, 0x64, 0x75, 0x01, 0xc9,
    0x7d, 0xdd, 0xe2, 0x0a, 0x4e, 0x71, 0xbe, 0x95, 0xfd, 0x5e, 0x71, 0x78,
    0x4e, 0x25, 0xac, 0xa4, 0xba, 0xf2, 0x5b, 0xe5, 0x73, 0x8a, 0xae, 0x59,
    0xbb, 0xfe, 0x1c, 0x99, 0x77, 0x81, 0x44, 0x7a, 0x2b, 0x24,
};

#if !defined(MBEDTLS_PSA_CRYPTO_C) || (MBEDTLS_VERSION_NUMBER < 0x02130000)
int main(void)
{
    printf("Not all of the requirements are met:\n"
           "  - MBEDTLS_PSA_CRYPTO_C\n"
           "  - PSA Crypto API v1.0b3\n");
    return 0;
}
#else

static void import_a_key(const uint8_t *key, size_t key_len)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t handle;

    printf("Import an AES key...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Set key attributes */
    psa_set_key_usage_flags(&attributes, 0);
    psa_set_key_algorithm(&attributes, 0);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);

    /* Import the key */
    status = psa_import_key(&attributes, key, key_len, &handle);
    if (status != PSA_SUCCESS) {
        printf("Failed to import key\n");
        return;
    }
    printf("Imported a key\n");

    /* Free the attributes */
    psa_reset_key_attributes(&attributes);

    /* Destroy the key */
    psa_destroy_key(handle);

    mbedtls_psa_crypto_free();
}

static void sign_a_message_using_rsa(const uint8_t *key, size_t key_len)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t hash[] = "INPUT_FOR_SIGN";
    uint8_t signature[PSA_ASYMMETRIC_SIGNATURE_MAX_SIZE] = {0};
    size_t signature_length;
    psa_key_handle_t handle;

    printf("Sign a message...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Set key attributes */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attributes, 1024);

    /* Import the key */
    status = psa_import_key(&attributes, key, key_len, &handle);
    if (status != PSA_SUCCESS) {
        printf("Failed to import key\n");
        return;
    }

    /* Sign message using the key */
    status = psa_asymmetric_sign(handle, PSA_ALG_RSA_PKCS1V15_SIGN_RAW,
                                 hash, sizeof(hash),
                                 signature, sizeof(signature),
                                 &signature_length);
    if (status != PSA_SUCCESS) {
        printf("Failed to sign\n");
        return;
    }

    printf("Signed a message\n");

    /* Free the attributes */
    psa_reset_key_attributes(&attributes);

    /* Destroy the key */
    psa_destroy_key(handle);

    mbedtls_psa_crypto_free();
}

static void encrypt_with_symmetric_ciphers(const uint8_t *key, size_t key_len)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE(PSA_KEY_TYPE_AES),
    };
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
    uint8_t plaintext[block_size] = SOME_PLAINTEXT;
    uint8_t iv[block_size];
    size_t iv_len;
    uint8_t output[block_size];
    size_t output_len;
    psa_key_handle_t handle;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

    printf("Encrypt with cipher...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Import a key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    status = psa_import_key(&attributes, key, key_len, &handle);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    /* Encrypt the plaintext */
    status = psa_cipher_encrypt_setup(&operation, handle, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin cipher operation\n");
        return;
    }
    status = psa_cipher_generate_iv(&operation, iv, sizeof(iv), &iv_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to generate IV\n");
        return;
    }
    status = psa_cipher_update(&operation, plaintext, sizeof(plaintext),
                               output, sizeof(output), &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to update cipher operation\n");
        return;
    }
    status = psa_cipher_finish(&operation, output + output_len,
                               sizeof(output) - output_len, &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish cipher operation\n");
        return;
    }
    printf("Encrypted plaintext\n");

    /* Clean up cipher operation context */
    psa_cipher_abort(&operation);

    /* Destroy the key */
    psa_destroy_key(handle);

    mbedtls_psa_crypto_free();
}

static void decrypt_with_symmetric_ciphers(const uint8_t *key, size_t key_len)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE(PSA_KEY_TYPE_AES),
    };
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    uint8_t ciphertext[block_size] = SOME_CIPHERTEXT;
    uint8_t iv[block_size] = ENCRYPTED_WITH_IV;
    uint8_t output[block_size];
    size_t output_len;
    psa_key_handle_t handle;

    printf("Decrypt with cipher...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Import a key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    status = psa_import_key(&attributes, key, key_len, &handle);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    /* Decrypt the ciphertext */
    status = psa_cipher_decrypt_setup(&operation, handle, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin cipher operation\n");
        return;
    }
    status = psa_cipher_set_iv(&operation, iv, sizeof(iv));
    if (status != PSA_SUCCESS) {
        printf("Failed to set IV\n");
        return;
    }
    status = psa_cipher_update(&operation, ciphertext, sizeof(ciphertext),
                               output, sizeof(output), &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to update cipher operation\n");
        return;
    }
    status = psa_cipher_finish(&operation, output + output_len,
                               sizeof(output) - output_len, &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish cipher operation\n");
        return;
    }
    printf("Decrypted ciphertext\n");

    /* Clean up cipher operation context */
    psa_cipher_abort(&operation);

    /* Destroy the key */
    psa_destroy_key(handle);

    mbedtls_psa_crypto_free();
}

static void hash_a_message(void)
{
    psa_status_t status;
    psa_algorithm_t alg = PSA_ALG_SHA_256;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    unsigned char input[] = { 'a', 'b', 'c' };
    unsigned char actual_hash[PSA_HASH_MAX_SIZE];
    size_t actual_hash_len;

    printf("Hash a message...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Compute hash of message  */
    status = psa_hash_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin hash operation\n");
        return;
    }
    status = psa_hash_update(&operation, input, sizeof(input));
    if (status != PSA_SUCCESS) {
        printf("Failed to update hash operation\n");
        return;
    }
    status = psa_hash_finish(&operation, actual_hash, sizeof(actual_hash),
                             &actual_hash_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish hash operation\n");
        return;
    }

    printf("Hashed a message\n");

    /* Clean up hash operation context */
    psa_hash_abort(&operation);

    mbedtls_psa_crypto_free();
}

static void verify_a_hash(void)
{
    psa_status_t status;
    psa_algorithm_t alg = PSA_ALG_SHA_256;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    unsigned char input[] = { 'a', 'b', 'c' };
    unsigned char expected_hash[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
        0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    size_t expected_hash_len = PSA_HASH_SIZE(alg);

    printf("Verify a hash...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Verify message hash */
    status = psa_hash_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin hash operation\n");
        return;
    }
    status = psa_hash_update(&operation, input, sizeof(input));
    if (status != PSA_SUCCESS) {
        printf("Failed to update hash operation\n");
        return;
    }
    status = psa_hash_verify(&operation, expected_hash, expected_hash_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to verify hash\n");
        return;
    }

    printf("Verified a hash\n");

    /* Clean up hash operation context */
    psa_hash_abort(&operation);

    mbedtls_psa_crypto_free();
}

static void generate_a_random_value(void)
{
    psa_status_t status;
    uint8_t random[10] = { 0 };

    printf("Generate random...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    status = psa_generate_random(random, sizeof(random));
    if (status != PSA_SUCCESS) {
        printf("Failed to generate a random value\n");
        return;
    }

    printf("Generated random data\n");

    /* Clean up */
    mbedtls_psa_crypto_free();
}

static void derive_a_new_key_from_an_existing_key(void)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    static const unsigned char key[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b };
    static const unsigned char salt[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    static const unsigned char info[] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
        0xf7, 0xf8, 0xf9 };
    psa_algorithm_t alg = PSA_ALG_HKDF(PSA_ALG_SHA_256);
    psa_key_derivation_operation_t operation =
        PSA_KEY_DERIVATION_OPERATION_INIT;
    size_t derived_bits = 128;
    size_t capacity = PSA_BITS_TO_BYTES(derived_bits);
    psa_key_handle_t base_key;
    psa_key_handle_t derived_key;

    printf("Derive a key (HKDF)...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Import a key for use in key derivation. If such a key has already been
     * generated or imported, you can skip this part. */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);
    status = psa_import_key(&attributes, key, sizeof(key), &base_key);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    /* Derive a key */
    status = psa_key_derivation_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin key derivation\n");
        return;
    }
    status = psa_key_derivation_set_capacity(&operation, capacity);
    if (status != PSA_SUCCESS) {
        printf("Failed to set capacity\n");
        return;
    }
    status = psa_key_derivation_input_bytes(&operation,
                                            PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt, sizeof(salt));
    if (status != PSA_SUCCESS) {
        printf("Failed to input salt (extract)\n");
        return;
    }
    status = psa_key_derivation_input_key(&operation,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          base_key);
    if (status != PSA_SUCCESS) {
        printf("Failed to input key (extract)\n");
        return;
    }
    status = psa_key_derivation_input_bytes(&operation,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            info, sizeof(info));
    if (status != PSA_SUCCESS) {
        printf("Failed to input info (expand)\n");
        return;
    }
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    status = psa_key_derivation_output_key(&attributes, &operation,
                                           &derived_key);
    if (status != PSA_SUCCESS) {
        printf("Failed to derive key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    printf("Derived key\n");

    /* Clean up key derivation operation */
    psa_key_derivation_abort(&operation);

    /* Destroy the keys */
    psa_destroy_key(derived_key);
    psa_destroy_key(base_key);

    mbedtls_psa_crypto_free();
}

static void authenticate_and_encrypt_a_message(void)
{
    psa_status_t status;
    static const uint8_t key[] = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF };
    static const uint8_t nonce[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B };
    static const uint8_t additional_data[] = {
        0xEC, 0x46, 0xBB, 0x63, 0xB0, 0x25,
        0x20, 0xC3, 0x3C, 0x49, 0xFD, 0x70 };
    static const uint8_t input_data[] = {
        0xB9, 0x6B, 0x49, 0xE2, 0x1D, 0x62, 0x17, 0x41,
        0x63, 0x28, 0x75, 0xDB, 0x7F, 0x6C, 0x92, 0x43,
        0xD2, 0xD7, 0xC2 };
    uint8_t *output_data = NULL;
    size_t output_size = 0;
    size_t output_length = 0;
    size_t tag_length = 16;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t handle;

    printf("Authenticate encrypt...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    output_size = sizeof(input_data) + tag_length;
    output_data = (uint8_t *)malloc(output_size);
    if (!output_data) {
        printf("Out of memory\n");
        return;
    }

    /* Import a key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    status = psa_import_key(&attributes, key, sizeof(key), &handle);
    psa_reset_key_attributes(&attributes);

    /* Authenticate and encrypt */
    status = psa_aead_encrypt(handle, PSA_ALG_CCM,
                              nonce, sizeof(nonce),
                              additional_data, sizeof(additional_data),
                              input_data, sizeof(input_data),
                              output_data, output_size,
                              &output_length);
    if (status != PSA_SUCCESS) {
        printf("Failed to authenticate and encrypt\n");
        return;
    }

    printf("Authenticated and encrypted\n");

    /* Clean up */
    free(output_data);

    /* Destroy the key */
    psa_destroy_key(handle);

    mbedtls_psa_crypto_free();
}

static void authenticate_and_decrypt_a_message(void)
{
    psa_status_t status;
    static const uint8_t key[] = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF };
    static const uint8_t nonce[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B };
    static const uint8_t additional_data[] = {
        0xEC, 0x46, 0xBB, 0x63, 0xB0, 0x25,
        0x20, 0xC3, 0x3C, 0x49, 0xFD, 0x70 };
    static const uint8_t input_data[] = {
        0x20, 0x30, 0xE0, 0x36, 0xED, 0x09, 0xA0, 0x45, 0xAF, 0x3C, 0xBA, 0xEE,
        0x0F, 0xC8, 0x48, 0xAF, 0xCD, 0x89, 0x54, 0xF4, 0xF6, 0x3F, 0x28, 0x9A,
        0xA1, 0xDD, 0xB2, 0xB8, 0x09, 0xCD, 0x7C, 0xE1, 0x46, 0xE9, 0x98 };
    uint8_t *output_data = NULL;
    size_t output_size = 0;
    size_t output_length = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t handle;

    printf("Authenticate decrypt...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    output_size = sizeof(input_data);
    output_data = (uint8_t *)malloc(output_size);
    if (!output_data) {
        printf("Out of memory\n");
        return;
    }

    /* Import a key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    status = psa_import_key(&attributes, key, sizeof(key), &handle);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    /* Authenticate and decrypt */
    status = psa_aead_decrypt(handle, PSA_ALG_CCM,
                              nonce, sizeof(nonce),
                              additional_data, sizeof(additional_data),
                              input_data, sizeof(input_data),
                              output_data, output_size,
                              &output_length);
    if (status != PSA_SUCCESS) {
        printf("Failed to authenticate and decrypt\n");
        return;
    }

    printf("Authenticated and decrypted\n");

    /* Clean up */
    free(output_data);

    /* Destroy the key */
    psa_destroy_key(handle);

    mbedtls_psa_crypto_free();
}

static void generate_and_export_a_public_key()
{
    enum {
        key_bits = 256,
    };
    psa_status_t status;
    size_t exported_length = 0;
    static uint8_t exported[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits)];
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t handle;

    printf("Generate a key pair...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Generate a key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN);
    psa_set_key_algorithm(&attributes,
                          PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1));
    psa_set_key_bits(&attributes, key_bits);
    status = psa_generate_key(&attributes, &handle);
    if (status != PSA_SUCCESS) {
        printf("Failed to generate key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    status = psa_export_public_key(handle, exported, sizeof(exported),
                                   &exported_length);
    if (status != PSA_SUCCESS) {
        printf("Failed to export public key %ld\n", status);
        return;
    }

    printf("Exported a public key\n");

    /* Destroy the key */
    psa_destroy_key(handle);

    mbedtls_psa_crypto_free();
}

int main(void)
{
    printf("-- Begin Mbed Crypto Getting Started --\n\n");
    
    int ret = 0;

    if((ret = mbedtls_platform_setup(NULL)) != 0) {
        mbedtls_printf("Platform initialization failed with error %d\r\n", ret);
        return 1;
    }

    import_a_key(AES_KEY, sizeof(AES_KEY));
    sign_a_message_using_rsa(RSA_KEY, sizeof(RSA_KEY));
    encrypt_with_symmetric_ciphers(AES_KEY, sizeof(AES_KEY));
    decrypt_with_symmetric_ciphers(AES_KEY, sizeof(AES_KEY));
    hash_a_message();
    verify_a_hash();
    generate_a_random_value();
    derive_a_new_key_from_an_existing_key();
    authenticate_and_encrypt_a_message();
    authenticate_and_decrypt_a_message();
    generate_and_export_a_public_key();

    mbedtls_platform_teardown(NULL);
    printf("\n-- End Mbed Crypto Getting Started --\n");

    return 0;
}
#endif /* MBEDTLS_PSA_CRYPTO_C */
