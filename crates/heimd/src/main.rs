fn main() {
    let result = heimd::run_from(std::env::args());
    print!("{}", result.stdout);
    eprint!("{}", result.stderr);
    std::process::exit(result.code);
}
