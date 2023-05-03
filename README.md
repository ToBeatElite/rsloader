# rsloader

A shellcode loading library mainly for windows, written using rustlang. I made this mainly as I was learning about basic malware/tooling development. The majority of the tecniques were taken from [OffensiveRust](https://github.com/trickster0/OffensiveRust). Anything needed to decrypt shellcode is stored in the outputed file itself, and extracted by the loader automatically, so its not that OPSEC as anyone analyzing this can decrypt the shellcode entirely just by obtaining that one outputed file. Disclaimer: I'm not an operator nor a maldev, I had made this for fun.

### featuring
- 2 shellcode encryption methods
- 2 shellcode importing/exporting formats
- 3 userland shellcode loading methods
- 2 kernelland shellcode loading methods 

### building

```bash
./build.sh
```
binaries will be then found in ./bins
