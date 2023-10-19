use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
}

fn main() {
    let _args = Args::parse();
}
