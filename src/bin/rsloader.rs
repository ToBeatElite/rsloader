use rsloader;

fn main() {
    let file_name = "lmao";
    let sc_object = import_sc(file_name);
    sc_object.load();
}
