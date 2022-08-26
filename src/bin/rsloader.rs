fn main() {
    let shellcode = include_bytes!("../../haha").to_vec();
    let my_aes_object = rsloader::AESShellCode::new(rsloader::ShellCode{sc:shellcode.clone()});
    let serialized_aes_object = bincode::serialize(&my_aes_object).unwrap();
    println!("{:?}", serialized_aes_object[0]);
    let decoded_aes_object: rsloader::AESShellCode = bincode::deserialize(&serialized_aes_object).unwrap();
    assert_eq!(my_aes_object.sc.sc, decoded_aes_object.sc.sc);

    let my_xor_object = rsloader::XoredShellCode::new(rsloader::ShellCode{sc:shellcode.clone()});
    let serialized_xor_object = bincode::serialize(&my_xor_object).unwrap();
    println!("{:?}", serialized_xor_object);
    let decoded_xor_object: rsloader::XoredShellCode = bincode::deserialize(&serialized_xor_object).unwrap();
    assert_eq!(my_xor_object.sc.sc, decoded_xor_object.sc.sc);
  
}
