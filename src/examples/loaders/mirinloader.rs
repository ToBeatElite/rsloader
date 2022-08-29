use rsloader::ShellCode;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("[+] usage: rsloader [input_path]");
        std::process::exit(0x0100);
    };

    let recovered_shellcode = ShellCode::from_image(&args[1]);
    recovered_shellcode.load();
}
