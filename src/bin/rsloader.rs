//use clap;
use rsloader;

fn main() {
   // let yaml = clap::load_yaml!("../../resources/rsloader_cli.yml");
    //let argv = clap::App::from_yaml(yaml).get_matches();

  //  let shellcode_path = argv.value_of("sc_path").unwrap();
    let bigbrain = "asd";
    let sc_object = rsloader::ShellCode::from_file(bigbrain);
    sc_object.load();
}
