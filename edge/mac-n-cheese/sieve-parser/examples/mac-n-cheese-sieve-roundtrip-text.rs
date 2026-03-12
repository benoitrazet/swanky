use std::io::{Cursor, Read};

use mac_n_cheese_sieve_parser::PrintingVisitor;
use swanky_error::{ErrorKind, WrapErr};

fn main() -> swanky_error::Result<()> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut input)
        .wrap_err_with(ErrorKind::OtherError, || {
            "Failed to read stdin.".to_string()
        })?;
    let parser = mac_n_cheese_sieve_parser::text_parser::RelationReader::new(Cursor::new(input))?;
    println!("{}", parser.header());
    println!("@begin");
    {
        let stdout = std::io::stdout();
        parser.read(&mut PrintingVisitor(stdout.lock()))?;
    }
    println!("@end");
    Ok(())
}
