# NFC-UID-Tool

This tool was written because of a need to write a UID to a block 0 writable Mifare Desfire clone. (7 byte UID.)
The long term goal of this project is to provide UID writing capabilities for all common NFC tags, and document the behavior simply, for people who are new to NFC.

Inspired in part by [rocky112358](https://github.com/rocky112358/ACS-ACR122U-Tool).

## Setup

```bash
sudo apt install swig
sudo apt install libpcsclite-dev
sudo pip3 install pyscard
sudo apt install pcscd
```

## Roadmap

- [X] Desfire UID support
- [ ] Mifare Classic support
