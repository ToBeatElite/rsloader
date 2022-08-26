use rsloader;

fn main() {
    
    let bigbrain = "asd";
    let sc_object = rsloader::ShellCode::from_file(bigbrain);
    sc_object.load();
}
