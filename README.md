# rsloader

A shellcode loader for linux and windows, written in rustlang. Currently supports XOR and AES encryption. All arguments neccessary for decryption are stored alongside the shellcode, seperated by null bytes, so make sure your shellcode dosent have null bytes, or it cant be decrypted properly.

### building

```bash
./build.sh
```