use fuse_mt;
use log::debug;
// use std::{io::{self, prelude::*}, fs, os::unix::prelude::FileExt};

mod crypt_fs;

use crypt_fs::CryptFS;

struct ConsoleLogger;

impl log::Log for ConsoleLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        println!("{}: {}: {}", record.target(), record.level(), record.args());
    }

    fn flush(&self) {}
}

static LOGGER: ConsoleLogger = ConsoleLogger;


// main function
fn main() -> std::io::Result<()> {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Debug);

    debug!("Starting up");

    let src_path = "src_dir";
    let mnt_path = "mnt_dir";
    let key = "012345689abcdefg";
    let crypt_fs = CryptFS::new(String::from(key), String::from(src_path), None);

    // print!("{}", crypt_fs.get_real_path(Path::new("/test.txt")).display());
    fuse_mt::mount(fuse_mt::FuseMT::new(crypt_fs, 1), &mnt_path, &[])?;

    return Ok(());
}
