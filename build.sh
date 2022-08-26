#!/bin/bash

rm -rf bins
mkdir bins
rustup target add x86_64-pc-windows-gnu

cargo build --release
mv target/release/rsloader bins/rsloader
mv target/release/rscrypter bins/rscrypter

cargo build --target x86_64-pc-windows-gnu --release
mv target/x86_64-pc-windows-gnu/release/rsloader.exe bins/rsloader.exe
mv target/x86_64-pc-windows-gnu/release/rscrypter.exe bins/rscrypter.exe

strip bins/*
