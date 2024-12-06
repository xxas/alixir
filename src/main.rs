use std::collections::HashSet;

use alixir::program::module::{Symbol, SymbolFlags};

fn main()
{
    let path        = std::env::args().nth(1).expect("usage: alixir <binary>");

    // initialize our program from path into the loader.
    let mut loader = alixir::program::Loader::from_path(path, 0)
        .expect("failed to initialize the program from path");

    // Load our program, dependencies and do complete linkage.
    loader.load().expect("failed to load the program");
}
