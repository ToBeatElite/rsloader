#!/bin/bash

rm -rf bins
mkdir bins

rustup target add x86_64-pc-windows-gnu
cargo build --target x86_64-pc-windows-gnu --release

mv target/x86_64-pc-windows-gnu/release/rscrypter.exe bins/rscrypter.exe
mv target/x86_64-pc-windows-gnu/release/rsloader.exe bins/rsloader.exe
mv target/x86_64-pc-windows-gnu/release/rsloader_CreateRemoteThread.exe bins/rsloader_CreateRemoteThread.exe
mv target/x86_64-pc-windows-gnu/release/rsloader_EnumSystemGeoID.exe bins/rsloader_EnumSystemGeoID.exe

mv target/x86_64-pc-windows-gnu/release/mirincrypter.exe bins/mirincrypter.exe
mv target/x86_64-pc-windows-gnu/release/mirinloader.exe bins/mirinloader.exe
mv target/x86_64-pc-windows-gnu/release/mirinloader_CreateRemoteThread.exe bins/mirinloader_CreateRemoteThread.exe
mv target/x86_64-pc-windows-gnu/release/mirinloader_EnumSystemGeoID.exe bins/mirinloader_EnumSystemGeoID.exe
