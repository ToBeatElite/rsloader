use rsloader;
use bincode;


fn main() {
    let shellcode = vec![1,1,1,2,2,2,3,3,3,4,4,4,5,5,5];
    let my_shellcode_object = rsloader::XoredShellCode::new(shellcode);
    println!("{:?}", my_shellcode_object.sc.sc, my_shellcode_object.xor_key);

    let encoded = bincode::serialize(&my_shellcode_object).unwrap();
}
