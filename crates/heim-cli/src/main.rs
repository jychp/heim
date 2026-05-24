fn main() {
    let result = heim_cli::run_from(std::env::args_os());

    print!("{}", result.stdout);
    eprint!("{}", result.stderr);
    std::process::exit(result.code);
}
