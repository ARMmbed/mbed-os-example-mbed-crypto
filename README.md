![](./resources/official_armmbed_example_badge.png)
# Running Mbed Crypto examples on Mbed OS
This repository contains a set of examples demonstrating the compilation and use of Mbed Crypto on Mbed OS.

List of examples contained within this repository:
* Example code snippets for using the library, with [documentation](https://github.com/ARMmbed/mbed-crypto/blob/development/docs/getting_started.md).

## Prerequisites
* Install <a href='https://github.com/ARMmbed/mbed-cli#installing-mbed-cli'>Mbed CLI</a>

## Import
The following are the steps required to install the application:
1. Clone the repository: `git clone https://github.com/ARMmbed/mbed-os-example-mbed-crypto.git`
1. Navigate to the "getting-started" example: `cd mbed-os-example-mbed-crypto/getting-started`
1. Deploy the Mbed OS project: `mbed deploy`

## Compile
To compile the example program use `mbed compile` while specifying the target platform and the compiler.
For example, in order to compile using the ARM GCC compiler and a K64F target platform use: `mbed compile -m K64F -t GCC_ARM`.

Once the compilation is completed successfully a binary file will be created: `./BUILD/K64F/GCC_ARM/getting-started.bin`

## Program your board
1. Connect your Mbed device to the computer over USB.
1. Copy the binary file (`getting-started.bin`) to the Mbed device.

## Run
1. Connect to the Mbed Device using a serial client application of your choice.
1. Press the reset button on the Mbed device to run the program.

The expected output from the first successful execution of the example program should be as follows:
```
-- Begin Mbed Crypto Getting Started --

Import an AES key...    Imported a key
Sign a message...       Signed a message
Encrypt with cipher...  Encrypted plaintext
Decrypt with cipher...  Decrypted ciphertext
Hash a message...       Hashed a message
Verify a hash...        Verified a hash
Generate random...      Generated random data
Derive a key (HKDF)...  Derived key
Authenticate encrypt... Authenticated and encrypted
Authenticate decrypt... Authenticated and decrypted
Generate a key pair...  Exported a public key

-- End Mbed Crypto Getting Started --
```

## Troubleshooting
If you have problems, you can review the [documentation](https://os.mbed.com/docs/latest/tutorials/debugging.html) for suggestions on what could be wrong and how to fix it.

## License and contributions

The software is provided under Apache-2.0 license. Contributions to this project are accepted under the same license. Please see [contributing.md](CONTRIBUTING.md) for more info.

This project contains code from other projects. The original license text is included in those source files. They must comply with our license guide.
