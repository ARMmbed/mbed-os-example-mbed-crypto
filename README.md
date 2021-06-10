![](./resources/official_armmbed_example_badge.png)
# Running PSA Crypto examples on Mbed OS
This repository contains an example demonstrating the compilation and use of PSA Crypto on Mbed OS.

## Prerequisites
This example requires the PSA Crypto API:
* On TF-M targets, this API is provided by TF-M and always enabled.
* On other targets, Mbed OS PSA can be enabled by adding `target.extra_labels_add": ["MBED_PSA_SRV"]`
to `target_overrides` in [`getting-started/mbed_app.json`](./getting-started/mbed_app.json). Note that
this cannot coexist with TF-M.

## Mbed OS build tools

### Mbed CLI 2
Starting with version 6.5, Mbed OS uses Mbed CLI 2. It uses Ninja as a build system, and CMake to generate the build environment and manage the build process in a compiler-independent manner. If you are working with Mbed OS version prior to 6.5 then check the section [Mbed CLI 1](#mbed-cli-1).
1. [Install Mbed CLI 2](https://os.mbed.com/docs/mbed-os/latest/build-tools/install-or-upgrade.html).
1. From the command-line, import the example: `mbed-tools import mbed-os-example-mbed-crypto`

### Mbed CLI 1
1. [Install Mbed CLI 1](https://os.mbed.com/docs/mbed-os/latest/quick-start/offline-with-mbed-cli.html).
1. From the command-line, import the example: `mbed import mbed-os-example-mbed-crypto`

## Building and running

1. Change the current directory to `mbed-os-example-mbed-crypto/getting-started`.
1. Connect a USB cable between the USB port on the board and the host computer.
1. Run the following command to build the example project, program the microcontroller flash memory and open a serial monitor:

    * Mbed CLI 2

    ```bash
    $ mbed-tools compile -m <TARGET> -t <TOOLCHAIN> --flash --sterm
    ```

    * Mbed CLI 1

    ```bash
    $ mbed compile -m <TARGET> -t <TOOLCHAIN> --flash --sterm
    ```

Your PC may take a few minutes to compile your code.

## Expected output
```
-- Begin PSA Crypto Getting Started --

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

-- End PSA Crypto Getting Started --
```

## Troubleshooting
If you have problems, you can review the [documentation](https://os.mbed.com/docs/latest/tutorials/debugging.html) for suggestions on what could be wrong and how to fix it.

## License and contributions

The software is provided under Apache-2.0 license. Contributions to this project are accepted under the same license. Please see [contributing.md](CONTRIBUTING.md) for more info.

This project contains code from other projects. The original license text is included in those source files. They must comply with our license guide.
