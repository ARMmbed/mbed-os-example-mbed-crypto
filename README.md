# Running Mbed-Crypto examples on Mbed-OS
This repository contains a set of examples demonstrating the compilation and use
of Mbed-Crypto on Mbed-OS.

List of examples contained within this repository:
* Cipher encrypt/decrypt using an AES key in cipher block chain (CBC) mode with no padding using a single block.
* Cipher encrypt/decrypt using an AES key in cipher block chain (CBC) mode with PKCS7 padding using multiple blocks.
* Cipher encrypt/decrypt using an AES key in counter (CTR) mode using multiple blocks.

## Prerequisites
* Install <a href='https://github.com/ARMmbed/mbed-cli#installing-mbed-cli'>Mbed-CLI</a>

## Deploy
The following are the steps required for deployment:
* Clone this repository: `git clone git@github.com:ARMmbed/mbed-os-example-mbed-crypto.git`
* CD to `mbed-os-example-mbed-crypto`
* Fetch Mbed-OS: `mbed deploy`

## Compile
To compile the example program use `mbed compile` while specifying the target platform and the compiler.
For example, in order to compile using the ARM GCC compiler and a K64F target platform use: `mbed compile -m K64F -t ARM`.

Once the compilation is completed successfully a binary file will be created: `./BUILD/K64F/GCC_ARM/mbed-os-example-mbed-crypto.bin`

## Run
The following are the steps required to run the example program:
* Connect the Mbed device to your computer over USB.
* Copy the binary file (`mbed-os-example-mbed-crypto.bin`) to the Mbed device.
* Connect to the Mbed Device using an ssh client application of your choice.
* Press the reset button on the Mbed device to run the program.

The expected output from a successful execution of the example program should be as follows:
```
cipher encrypt/decrypt AES CBC no padding:
        success!
cipher encrypt/decrypt AES CBC PKCS7 multipart:
        success!
cipher encrypt/decrypt AES CTR multipart:
        success!
```
