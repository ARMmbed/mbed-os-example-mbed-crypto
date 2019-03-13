# Running Mbed Crypto examples on Mbed OS
This repository contains a set of examples demonstrating the compilation and use of Mbed Crypto on Mbed OS.

List of examples contained within this repository:
* Cipher encrypt/decrypt using an AES key in cipher block chain (CBC) mode with no padding using a single block.
* Cipher encrypt/decrypt using an AES key in cipher block chain (CBC) mode with PKCS7 padding using multiple blocks.
* Cipher encrypt/decrypt using an AES key in counter (CTR) mode using multiple blocks.

## Factory injection of entropy

This example also contains a fake entropy injection example. Use of this
function (`mbedtls_psa_inject_entropy()`) is demonstrated in this example, but
it is not a function users would ever need to call as part of their
applications. The function is useful for factory tool developers only.

In a production system, and in the absence of other sources of entropy, a
factory tool can inject entropy into the device. After the factory tool
completes manufacturing of a device, that device must contain enough entropy
for the lifetime of the device or be able to produce it with an on-board TRNG.

A factory application wishing to inject entropy should configure Mbed Crypto
using the Mbed TLS configuration system (for the PSA Secure Processing Element,
SPE), such as in the factory application's SPE binary's `mbed_app.json` as
follows:

```javascript
{
    "macros": [
        "MBEDTLS_ENTROPY_NV_SEED=1",
        "MBEDTLS_PLATFORM_NV_SEED_READ_MACRO=mbed_default_seed_read",
        "MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO=mbed_default_seed_write"
    ]
}
```

## Prerequisites
* Install <a href='https://github.com/ARMmbed/mbed-cli#installing-mbed-cli'>Mbed CLI</a>

## Import
The following are the steps required to install the application:
* Clone the repository and deploy the Mbed OS project: `mbed import https://github.com/ARMmbed/mbed-os-example-mbed-crypto`
* Change your current directory: `cd mbed-os-example-mbed-crypto`

## Compile
To compile the example program use `mbed compile` while specifying the target platform and the compiler.
For example, in order to compile using the ARM GCC compiler and a K64F target platform use: `mbed compile -m K64F -t GCC_ARM`.

Once the compilation is completed successfully a binary file will be created: `./BUILD/K64F/GCC_ARM/mbed-os-example-mbed-crypto.bin`

## Program your board
1. Connect your Mbed device to the computer over USB.
1. Copy the binary file (`mbed-os-example-mbed-crypto.bin`) to the Mbed device.

## Run
1. Connect to the Mbed Device using a serial client application of your choice.
1. Press the reset button on the Mbed device to run the program.

The expected output from a successful execution of the example program should be as follows:
```
cipher encrypt/decrypt AES CBC no padding:
        success!
cipher encrypt/decrypt AES CBC PKCS7 multipart:
        success!
cipher encrypt/decrypt AES CTR multipart:
        success!
```

## Troubleshooting
If you have problems, you can review the [documentation](https://os.mbed.com/docs/latest/tutorials/debugging.html) for suggestions on what could be wrong and how to fix it.

