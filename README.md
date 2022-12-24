# "CFW" Toolkit

With the proper keys, all of which can be obtained from the console, you can decrypt AND properly encrypt the following binary images:

- EAP KBL (Kernel Boot Loader)
- EAP Kernel
- EMC IPL (Initial Program Load)
- Syscon (Both Patch and Full)

What's missing as far as custom code running EVERYWHERE, that's not currently supported within this repo:

- SAMU IPL (Encrypted with PCKs within Sflash and signed with private keys)
  - Required for PS3 style CFW where you just install a PUP
  - Private keys are NOT on the console
  - Seven revisions
- SELF Files (Encrypted and signed with private keys)
  - Would not matter if SAMU IPL is broken/custom
  - Private keys are NOT on the console
- WiFi FW (Not encrypted or signed. One of them is packed, it's just a ZIP)
  - Three revisions
- BD Drive FW (Haven't looked at it)
  - Six revisions
- USB SATA Bridge FW (Haven't looked at it)
  - One revision
- Communication Processor FW (Haven't looked at it)
  - Devkit only
  - One revision

## Requirements

- C++ Compiler (Clang >= 9.00 Recommended)
- CMake >=3.10.2
- [gflags](https://github.com/gflags/gflags)
- [glog](https://github.com/google/glog)
- OpenSSL (1.1.1 Recommended)
  - \>=3.0.0 will raising warnings for depreciated low level API usage. With the included C++ flags warning are errors.

## EAP

### Synopsis

Decrypts/Encrypts EAP KBL (Kernel Boot Loader) images. Located at /dev/sflash0s0x33

### Usage

Flags
> -decrypt (Run in decryption mode) type: bool default: false<br>
> -encrypt (Run in encryption mode) type: bool default: false<br>
> -input (Path of the EAP KBL file to load) type: string default: "C0010001"<br>
> -keys (Path of the key file to load) type: string default: "keys.json"<br>
> -output (Path to save the output EAP KBL file) type: string default: "C0010001.modified"<br>
> -revision (Which southbridge revision keyset to use. Only used for encryption ("AEOLIA", "BELIZE", "BELIZE 2", or "BAIKAL")) type: string default: ""

## EAPK

### Synopsis

Decrypts/Encrypts EAP Kernel images. Located at /dev/da0x2

### Usage

Flags
> -decrypt (Run in decryption mode) type: bool default: false<br>
> -encrypt (Run in encryption mode) type: bool default: false<br>
> -input (Path of the EAP kernel file to load) type: string default: "eap_kernel"<br>
> -keys (Path of the key file to load) type: string default: "keys.json"<br>
> -keyset (Which keyset to use. Only used for encryption ("0", "1", "2", or "3")) type: int32 default: -1<br>
> -output (Path to save the output EAP kernel file) type: string default: "eap_kernel.modified"

## EMC

### Synopsis

Decrypts/Encrypts EMC images. Can apply "Godmode" patches during either operation. Located at /dev/sflash0s0x32b

### Usage

Flags
> -decrypt (Run in decryption mode) type: bool default: false<br>
> -encrypt (Run in encryption mode) type: bool default: false<br>
> -godmode (Should "Godmode" patches be applied) type: bool default: false<br>
> -input (Path of the EMC IPL file to load) type: string default: "C0000001"<br>
> -keys (Path of the key file to load) type: string default: "keys.json"<br>
> -output (Path to save the output EAP KBL file) type: string default: "C0000001.modified"<br>
> -revision (Which southbridge revision keyset to use. Only used for encryption ("AEOLIA", "BELIZE", "BELIZE 2", or "BAIKAL")) type: string default: ""

## Syscon

### Synopsis

Decrypts/Encrypts SYSCON images. Inaccessible from filsystem

### Usage

Flags
> -decrypt (Run in decryption mode) type: bool default: false<br>
> -encrypt (Run in encryption mode) type: bool default: false<br>
> -input (Path of the SYSCON file to load) type: string default: "40000001"<br>
> -keys (Path of the key file to load) type: string default: "keys.json"<br>
> -output (Path to save the output SYSCON file) type: string default: "40000001.modified"

## Notes

- This is tested on WSL with Clang 10 and OpenSSL 1.1.1, support for anything else is not guaranteed.
- Output binary files will be located in `bin/`
- The input binary for encryption doesn't do any checks beyond checking to see if the file magic is correct and the file size will fit the free space available when installed. It's your responsibility to make sure the binary you're feeding it is built correctly/valid.
- This is stripped out of a larger project so somethings may not make since/be optimal in this context, however it should function as expected. I did my best minimizing it without rewriting any of it. Any major changes in functionality may not work within the context of the larger program (Or already be done) so send me a DM before starting to work on major changes.
  - Some features were removed to not step on toes and will likely be added at a later date. No ETA.
- Keys not included, check the dev wiki or something. This is on purpose... do not submit them please, update the wiki if you're adding new ones.
- Be sure to have a way to restore from a backup if you are using real hardware
