use fuse_mt;
use log::{debug, info};
use std::process::Command;
use ctrlc;

mod crypt_fs;
use crypt_fs::CryptFS;

struct ConsoleLogger;
static LOGGER: ConsoleLogger = ConsoleLogger;
impl log::Log for ConsoleLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        println!("{}: {}: {}", record.target(), record.level(), record.args());
    }

    fn flush(&self) {}
}


/// TODO: Take arguments from command line
fn main() -> std::io::Result<()> {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Debug);

    debug!("Starting up");

    let src_path = "src_dir";
    let mnt_path = "mnt_dir";
    let key = "012345689abcdefg";
    let crypt_fs = CryptFS::new(String::from(key), String::from(src_path), None);

    ctrlc::set_handler(move || {
        info!("Unmounting and exiting");
        Command::new("umount").arg(mnt_path).spawn().expect("Error unmounting");
    }).expect("Error setting Ctrl-C handler");

    fuse_mt::mount(fuse_mt::FuseMT::new(crypt_fs, 1), mnt_path, &[])?;

    return Ok(());
}
