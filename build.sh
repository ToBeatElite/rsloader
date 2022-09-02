#!/bin/bash

rm -rf bins
mkdir bins
mkdir bins/loaders bins/crypters

rustup target add x86_64-pc-windows-gnu
cargo build --target x86_64-pc-windows-gnu --release

mv target/x86_64-pc-windows-gnu/release/rscrypter.exe bins/crypters/rscrypter.exe

mv target/x86_64-pc-windows-gnu/release/rsloader.exe bins/loaders/rsloader.exe
mv target/x86_64-pc-windows-gnu/release/rsloader_CreateRemoteThread.exe bins/loaders/rsloader_CreateRemoteThread.exe
mv target/x86_64-pc-windows-gnu/release/rsloader_EnumSystemGeoID.exe bins/loaders/rsloader_EnumSystemGeoID.exe
mv target/x86_64-pc-windows-gnu/release/rsloader_direct_syscalls.exe bins/loaders/rsloader_direct_syscalls.exe
mv target/x86_64-pc-windows-gnu/release/rsloader_NtCreateThreadEx.exe bins/loaders/rsloader_NtCreateThreadEx.exe


mv target/x86_64-pc-windows-gnu/release/mirincrypter.exe bins/crypters/mirincrypter.exe
mv target/x86_64-pc-windows-gnu/release/mirinloader.exe bins/loaders/mirinloader.exe
mv target/x86_64-pc-windows-gnu/release/mirinloader_CreateRemoteThread.exe bins/loaders/mirinloader_CreateRemoteThread.exe
mv target/x86_64-pc-windows-gnu/release/mirinloader_EnumSystemGeoID.exe bins/loaders/mirinloader_EnumSystemGeoID.exe
mv target/x86_64-pc-windows-gnu/release/mirinloader_direct_syscalls.exe bins/loaders/mirinloader_direct_syscalls.exe
mv target/x86_64-pc-windows-gnu/release/mirinloader_NtCreateThreadEx.exe bins/loaders/mirinloader_NtCreateThreadEx.exe
