use rsloader;

fn import_sc(input_path: &str) -> rsloader::ShellCode {
    let sc_object = match rsloader::ShellCode::from_file(input_path, "xor") {
        Ok(my_xor_object) => my_xor_object,
        Err(_) => {
            match rsloader::ShellCode::from_file(input_path, "aes") {
                Ok(my_aes_object) => my_aes_object,
                Err(_) => rsloader::ShellCode::from_file(input_path, "plain").unwrap()
            }
        }   
    };

    sc_object
}
fn main() {
    let file_name = "lmao";
    let sc_object = import_sc(file_name);
    sc_object.load();
}
