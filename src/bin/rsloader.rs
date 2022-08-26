use rsloader;

fn main() {
    let file_name = "lmao";
    let sc_object = from_file(file_name);
    sc_object.load();
}
