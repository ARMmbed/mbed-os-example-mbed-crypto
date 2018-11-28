# Running Mbed Crypto examples on Mbed OS
This repository contains a set of examples demonstrating the compilation and use of Mbed Crypto on Mbed OS.

List of examples contained within this repository:
* Cipher encrypt/decrypt using an AES key in cipher block chain (CBC) mode with no padding using a single block.
* Cipher encrypt/decrypt using an AES key in cipher block chain (CBC) mode with PKCS7 padding using multiple blocks.
* Cipher encrypt/decrypt using an AES key in counter (CTR) mode using multiple blocks.

## Prerequisites
* Install <a href='https://github.com/ARMmbed/mbed-cli#installing-mbed-cli'>Mbed CLI</a>

## Import
The following are the steps required for install the application:
* Clone the repository and deploy the Mbed OS project: `mbed import https://github.com/ARMmbed/mbed-os-example-mbed-crypto`
* Change your current directory: `cd mbed-os-example-mbed-crypto`

## Compile
To compile the example program use `mbed compile` while specifying the target platform and the compiler.
For example, in order to compile using the ARM GCC compiler and a K64F target platform use: `mbed compile -m K64F -t ARM`.

Once the compilation is completed successfully a binary file will be created: `./BUILD/K64F/GCC_ARM/mbed-os-example-mbed-crypto.bin`

## Program your board
1. Connect your mbed device to the computer over USB.
1. Copy the binary file to the mbed device.
1. Press the reset button to start the program.

## Run
The following are the steps required to run the example program:
* Connect the Mbed device to your computer over USB.
* Copy the binary file (`mbed-os-example-mbed-crypto.bin`) to the Mbed device.
* Connect to the Mbed Device using a serial client application of your choice.
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

## Troubleshooting
If you have problems, you can review the [documentation](https://os.mbed.com/docs/latest/tutorials/debugging.html) for suggestions on what could be wrong and how to fix it.

