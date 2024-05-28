use std::ffi::{OsStr, OsString};
use std::mem::forget;
use std::os;
use std::os::fd::{IntoRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::{fs, os::linux::fs::MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use fuse_mt::*;
use libc;

#[allow(unused_imports)]
use log::{debug, error, info};

use super::{CryptFS, CryptFSError, CryptFSMode, CryptMode};

const TTL: Duration = Duration::from_secs(1);
const CRYPT_FLAG_POS: u8 = 63;


trait CryptFSFuse {
    fn get_real_root(&self, path: &Path) -> PathBuf;
    fn toggle_extension(path: &Path) -> std::path::PathBuf;
    fn is_path_allowed(path: &Path) -> bool;
    fn is_dir(path: &Path) -> bool;
    fn is_file(path: &Path) -> bool;
    fn get_crypt_dir_real_name(&self, path: &Path) -> Result<PathBuf, CryptFSError>;
    fn get_crypt_file_real_name(&self, path: &Path) -> Result<PathBuf, CryptFSError>;
    fn get_source_path(&self, path: &Path) -> Result<PathBuf, libc::c_int>;
    fn get_crypt_mode(&self, path: &Path) -> CryptMode;
}


impl CryptFSFuse for CryptFS {

    /// Returns the real path of a file
    /// This is used by the fuse module to get the real path of a fuse file
    /// # Arguments
    /// * `path` - Path of the fuse file
    /// 
    /// # Returns
    /// The real path of the file
    /// 
    /// # Panics
    /// This will panic if the Path is empty (no "/" in path)
    fn get_real_root(&self, path: &Path) -> PathBuf {
        let mut real_path = self.src_dir.clone();
        real_path.push(path.strip_prefix("/").unwrap());
        return real_path;
    }

    /// Add or remove the .crypt extension from a path
    /// If the file already has the .crypt extension, it will be removed
    /// If the file does not have the .crypt extension, it will be appended
    /// 
    /// # Arguments
    /// A path to toggle the extension of
    /// 
    /// # Returns
    /// Path with .crypt extension added or removed
    fn toggle_extension(path: &Path) -> std::path::PathBuf {
        let mut path_buf = path.to_path_buf();
        let ext = path_buf.extension();

        if ext == Some(OsStr::new("crypt")) {
            path_buf.set_extension("");
        } else {
            let new_extention = match ext {
                Some(ext) => format!("{}.crypt", ext.to_str().unwrap()),
                None => String::from("crypt"),
            };

            path_buf.set_extension(new_extention);
        }
        
        return path_buf;
    }

    /// Checks if the path is a regular file or directory
    /// It will reject symlinks and special files
    /// 
    /// # Arguments
    /// Source file path
    /// 
    /// # Returns
    /// `true` if path is a regular file or directory
    /// `false` if path is not a regular file or directory
    #[inline]
    fn is_path_allowed(path: &Path) -> bool {
        return (path.is_dir()|| path.is_file()) && !path.is_symlink();
    }

    /// Checks if the path is a directory
    /// It will reject symlinks and special files
    /// 
    /// # Arguments
    /// Path of the directory to check
    /// 
    /// # Returns
    /// `true` if path is a directory
    /// `false` if path is not a directory or is a symlink
    #[inline]
    fn is_dir(path: &Path) -> bool {
        return path.is_dir() && !path.is_symlink();
    }

    /// Checks if the path is a regular file
    /// It will reject symlinks and special files
    /// 
    /// # Arguments
    /// Path of the file to check
    /// 
    /// # Returns
    /// `true` if path is a regular file
    /// `false` if path is not a regular file or is a symlink
    #[inline]
    fn is_file(path: &Path) -> bool {
        return path.is_file() && !path.is_symlink();
    }

    #[inline]
    fn get_crypt_dir_real_name(&self, path: &Path) -> Result<PathBuf, CryptFSError> {

        let parent = path.parent().unwrap_or(Path::new("/"));
        let dir_data_path = parent.join(format!(".{}.{}", path.file_name().unwrap().to_str().unwrap(), "dir"));

        if CryptFS::is_file(dir_data_path.as_path()) {
            let dir_data_file = fs::File::open(&dir_data_path)?;
            let header = self.read_header(&dir_data_file)?;
            Ok(PathBuf::from(header.get_file_name()))
        } else {
            Ok(path.to_path_buf())  // no metadata file, return the original path
        }
    }

    fn get_crypt_file_real_name(&self, path: &Path) -> Result<PathBuf, CryptFSError> {
        let file = fs::File::open(path)?;
        let header = self.read_header(&file)?;
        Ok(PathBuf::from(header.get_file_name()))
    }

    /// Returns the real path of a file
    /// This is used by the fuse module to get the real path of a fuse file
    /// This involves modifyin the directory path and adding or removing the .crypt extension (for files)
    /// 
    /// # Arguments
    /// Path of the fuse file
    /// 
    /// # Returns
    /// Path of the source file
    /// 
    /// # Errors
    /// `libc::ENOENT` - If the source file does not exist
    /// 
    /// *TODO:* implement using a hash map, there is no good efficent way to 
    /// find the correct directory when encrypting with hide_file_names enabled
    /// as this requires a "guess and check" method
    fn get_source_path(&self, path: &Path) -> Result<PathBuf, libc::c_int> {


        let path = path.canonicalize().unwrap();

        // The source root is the one exception to the rule, as this is decided by the user
        // and the folder name is not encrypted
        if path == Path::new("/") {
            return Ok(self.src_dir.clone());
        }

        let real_path = match self.fpath_map.get(self.get_real_root(&path).as_path()) {
            Some(real_path) => real_path,
            None => {
                self.log_error(CryptFSError::InvalidPath, Some(&path));
                return Err(libc::ENOENT);
            }
        };

        // check to make sure the path is a regular file or directory
        if !CryptFS::is_path_allowed(real_path) {
            self.log_error(CryptFSError::InvalidPath, Some(&path));
            return Err(libc::ENOENT);
        }

        Ok(real_path.clone())
    }

    
    /// Gets the the crypt mode based on the file extension
    /// If the source file has the .crypt extension, it will be decrypted
    /// If the source file does not have the .crypt extension, it will be encrypted
    /// 
    /// # Arguments
    /// `&Path` - Path of the fuse file
    /// 
    /// # Returns
    /// `CryptMode::Decrypt` - If the file has the .crypt extension
    fn get_crypt_mode(&self, path: &Path) -> CryptMode {  // TODO: Enforce encrypt/decrpyt only mode

        match self.options.mode {
            CryptFSMode::EncryptOnly => return CryptMode::Encrypt,
            CryptFSMode::DecryptOnly => return CryptMode::Decrypt,
            CryptFSMode::Auto => {
                if path.extension() == Some(OsStr::new("crypt")) {
                    return CryptMode::Decrypt;
                } else {
                    return CryptMode::Encrypt;
                }
            },
        };
    }
}



impl FilesystemMT for CryptFS {
    fn init(&self, _req: RequestInfo) -> ResultEmpty {
        debug!("init() called");
        return Ok(());
    }

    fn destroy(&self) {
        debug!("destroy() called");
    }

    /// Gets attributes of a source file
    /// This will modify the size of the source file to match the size
    /// after encryption
    fn getattr(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>) -> ResultEntry {
        debug!("getattr() called");

        let source_path = CryptFS::get_source_path(&self, _path)?;

        let file = match fs::File::open(&source_path) {
            Ok(file) => file,
            Err(_) => {
                self.log_error(CryptFSError::InvalidPath, Some(_path));
                return Err(libc::ENOENT);
            },
        };
            
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(_) => return Err(libc::ENOENT),
        };

        let size = match metadata.is_dir() {
            true => metadata.len(),
            false => {
                let mode = self.get_crypt_mode(&source_path);
                match self.get_crypt_read_size(&file, mode) {
                    Ok(size) => size,
                    Err(e) => {
                        self.log_error(e, Some(_path));
                        return Err(libc::EIO);
                    }
                }
            }
        };
        
        let f_attr = FileAttr {
            size: size,
            blocks: metadata.st_blocks(),
            atime: metadata.accessed().unwrap(),
            mtime: metadata.modified().unwrap(),
            ctime: metadata.created().unwrap(),
            crtime: metadata.accessed().unwrap(),       // linux doesn't have creation time
            kind: if metadata.is_dir() { FileType::Directory } else { FileType::RegularFile },
            perm: (metadata.st_mode() & 0xffff) as u16,
            nlink: metadata.st_nlink() as u32,
            uid: metadata.st_uid(),
            gid: metadata.st_gid(),
            rdev: metadata.st_rdev() as u32,
            flags: 0        // macOS only, not supported on linux
        };

        return Ok((TTL,f_attr));
    }

    fn chmod(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _mode: u32) -> ResultEmpty {
        debug!("chmod() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn chown(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _uid: Option<u32>, _gid: Option<u32>) -> ResultEmpty {
        debug!("chown() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn truncate(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _size: u64) -> ResultEmpty {
        debug!("truncate() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn utimens(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _atime: Option<SystemTime>, _mtime: Option<SystemTime>) -> ResultEmpty {
        debug!("utimens() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn utimens_macos(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _crtime: Option<std::time::SystemTime>, _chgtime: Option<std::time::SystemTime>, _bkuptime: Option<std::time::SystemTime>, _flags: Option<u32>) -> ResultEmpty {
        debug!("utimens_macos() called");
        return Err(libc::EROFS)     //read only filesystem & macOS only
    }

    fn readlink(&self, _req: RequestInfo, _path: &Path) -> ResultData {
        debug!("readlink() called");
        // there should be no symlinks in this filesystem
        return Err(libc::EINVAL);
    }

    fn mknod(&self, _req: RequestInfo, _parent: &Path, _name: &std::ffi::OsStr, _mode: u32, _rdev: u32) -> ResultEntry {
        debug!("mknod() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn mkdir(&self, _req: RequestInfo, _parent: &Path, _name: &std::ffi::OsStr, _mode: u32) -> ResultEntry {
        debug!("mkdir() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn unlink(&self, _req: RequestInfo, _parent: &Path, _name: &std::ffi::OsStr) -> ResultEmpty {
        debug!("unlink() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn rmdir(&self, _req: RequestInfo, _parent: &Path, _name: &std::ffi::OsStr) -> ResultEmpty {
        debug!("rmdir() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn symlink(&self, _req: RequestInfo, _parent: &Path, _name: &std::ffi::OsStr, _target: &Path) -> ResultEntry {
        debug!("symlink() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn rename(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr, _newparent: &Path, _newname: &OsStr) -> ResultEmpty {
        debug!("rename() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn link(&self, _req: RequestInfo, _path: &Path, _newparent: &Path, _newname: &std::ffi::OsStr) -> ResultEntry {
        debug!("link() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn open(&self, _req: RequestInfo, _path: &Path, _flags: u32) -> ResultOpen {
        debug!("open() called");

        let source_path = self.get_source_path(_path)?; // get source path and check if it exists
        
        // TODO: check requested flags
        // if _flags == (libc::O_CREAT as u32 || libc::O_EXCL as u32) {
        //     // file creation not supported
        //     return Err(libc::EROFS);
        // }

        // get file handle
        let mut fd = fs::OpenOptions::new().read(true).open(&source_path).unwrap().into_raw_fd() as u64;
        let flags = libc::O_RDONLY as u32;

        // We add a bit to the front of the fd to indicate if the file is encrypted or not
        // First check if MSB bit is set, this *should* never happen (it technically could, but it's very unlikely)
        // as the fd is incremented by 1 each time a file is opened, we should never need to open more than 2^63 files
        if fd & (1 << CRYPT_FLAG_POS) != 0 {
            self.log_error(anyhow::anyhow!("File descriptor MSB bit is set, this should never happen").into(), Some(_path));
            return Err(libc::EIO);
        }
        let mode = self.get_crypt_mode(&source_path);
        fd = fd | ((mode as u64) << CRYPT_FLAG_POS);

        return Ok((fd, flags));
    }

    fn read(&self, _req: RequestInfo, _path: &Path, _fh: u64, _offset: u64, _size: u32, callback: impl FnOnce(ResultSlice<'_>) -> CallbackResult) -> CallbackResult {
        debug!("read() called");

        let mode = if (_fh >> CRYPT_FLAG_POS) == CryptMode::Decrypt as u64 { CryptMode::Decrypt } else { CryptMode::Encrypt };

        let _fh = _fh & !(1 << CRYPT_FLAG_POS);     // Clear bit if set

        let file = unsafe { fs::File::from_raw_fd(_fh as i32) };

        let file_size = match file.metadata()   {
            Ok(m) => m.len(),
            Err(_) => {
                self.log_error(CryptFSError::InvalidFileSize, Some(_path));
                return callback(Err(libc::EIO));
            }
        };

        let crypt_file: Vec<u8>;

        match mode {
            CryptMode::Encrypt => {
                let filename = match _path.file_name() {
                    Some(n) => n,
                    None => {
                        self.log_error(CryptFSError::InvalidPath, Some(_path));
                        return callback(Err(libc::ENOENT));
                    }
                };

                crypt_file = match self.encrypt_file(&file, filename.as_bytes()) {
                    Ok(data) => data,
                    Err(e) => {
                        self.log_error(e, Some(_path));
                        return callback(Err(libc::EIO));
                    }
                };
            }

            CryptMode::Decrypt => {
                crypt_file = match self.decrypt_file(&file) {
                    Ok((data, _)) => data,
                    Err(e) => {
                        self.log_error(e, Some(_path));
                        return callback(Err(libc::EIO));
                    }
                };
            }
        }

        

        if _offset > crypt_file.len() as u64 {
            return callback(Ok(&[]));
        }

        let file_part;

        if _size as u64 + _offset > crypt_file.len() as u64 {
            file_part = &crypt_file[_offset as usize..];
        } else {
            file_part = &crypt_file[_offset as usize.._offset as usize + _size as usize];
        }
        
        forget(file);   // or rust will close the file when it goes out of scope, which is a no-no
        return callback(Ok(file_part));
    }

    fn write(&self, _req: RequestInfo, _path: &Path, _fh: u64, _offset: u64, _data: Vec<u8>, _flags: u32) -> ResultWrite {
        debug!("write() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn flush(&self, _req: RequestInfo, _path: &Path, _fh: u64, _lock_owner: u64) -> ResultEmpty {
        debug!("flush() called");
        return Ok(());  // TODO: implement locking, maybe...
    }

    fn release(&self, _req: RequestInfo, _path: &Path, _fh: u64, _flags: u32, _lock_owner: u64, _flush: bool) -> ResultEmpty {
        debug!("release() called");
        
        // convert fd to file
        let file = unsafe { fs::File::from_raw_fd(_fh as i32) };    // rust will close the file when it goes out of scope
        drop(file);
        return Ok(());
    }

    fn fsync(&self, _req: RequestInfo, _path: &Path, _fh: u64, _datasync: bool) -> ResultEmpty {
        debug!("fsync() called");
        // read only filesystem, so nothing to do
        return Ok(())
    }

    fn opendir(&self, _req: RequestInfo, _path: &Path, _flags: u32) -> ResultOpen {
        debug!("opendir() called");
        let source_path = self.get_source_path(_path)?;
        let handle = fs::File::open(source_path).unwrap().into_raw_fd() as u64;
        return Ok((handle, 0));
    }

    // TODO: Redo this function with the option of hiding file names
    fn readdir(&mut self, _req: RequestInfo, _path: &Path, _fh: u64) -> ResultReaddir {
        // It would be better to use the libc::readdir() function, but for now I'll just use rust's fs::read_dir()
        debug!("readdir() called");

        let search_path = self.get_source_path(_path)?;

        if !search_path.is_dir() {
            return Err(libc::ENOTDIR);
        }


        let mut entries: Vec<DirectoryEntry> = Vec::new();

        // read_dir needs to open the file again, as it calls both opendir() and readdir() and readir underneath
        for entry in fs::read_dir(search_path.as_path()).unwrap()  {
            let entry = entry.unwrap();
            let source_path = entry.path();
            let orig_file_name = PathBuf::from(entry.file_name());

            // make sure is either regular file or directory
            if !CryptFS::is_path_allowed(&source_path) {
                continue;
            }

            let new_file_name: OsString;

            match self.get_crypt_mode(&source_path) {
                CryptMode::Encrypt => {

                    let new_name = if self.options.hide_file_names {
                        // hide the file name behind a hmac
                        match self.get_crypt_filename(&orig_file_name.to_string_lossy()) {
                            Ok(name) => name,
                            Err(e) => {
                                self.log_error(e, Some(_path));
                                continue;
                            }
                        }
                    } else {
                        // just add the .crypt extension
                        orig_file_name.to_string_lossy().to_string()
                    };

                    new_file_name = CryptFS::toggle_extension(&PathBuf::from(new_name)).into();

                    // directories have an additional (virtual) file that will be added later
                    if source_path.is_dir() {
                        let dir_file_name = OsStr::new(format!(".{}.{}", new_name, "dir").as_str());

                        entries.push(DirectoryEntry {
                            name: dir_file_name.to_os_string(),
                            kind: FileType::RegularFile
                        });
                    }
                },
                CryptMode::Decrypt => {

                    let new_name = if CryptFS::is_file(&source_path) {
                        match self.get_crypt_file_real_name(&source_path) {
                            Ok(name) => name,
                            Err(e) => {
                                self.log_error(e, Some(_path));
                                continue;
                            }
                        }
                    } else {
                        match self.get_crypt_dir_real_name(&source_path) {
                            Ok(name) => name,
                            Err(e) => {
                                self.log_error(e, Some(_path));
                                continue;
                            }
                        }
                    };

                    new_file_name = new_name.into();
                }
            }

            // update hash map with new file name
            let mut new_path = source_path.clone();
            new_path.set_file_name(new_file_name.clone());
            self.fpath_map.insert(new_path, source_path);
            
            // if !source_path.is_dir() {
            //     if source_path.extension() == Some(OsStr::new("crypt")) {
            //         let file = match fs::File::open(&source_path) {
            //             Ok(file) => file,
            //             Err(_) => {
            //                 self.log_error(CryptFSError::InvalidPath, Some(_path));
            //                 continue;
            //             },
            //         };
                
            //         let header = match self.read_header(&file) {
            //             Ok(header) => header,
            //             Err(e) => {
            //                 self.log_error(e, Some(_path));
            //                 continue;
            //             }
            //         };

            //         let orig_name = OsStr::from_bytes(
            //             // remove zero padding from file name
            //             &header.file_name[..header.file_name.iter().position(|&x| x == 0).unwrap_or(header.file_name.len())]
            //         );
            //         path = PathBuf::from(source_path.with_file_name(orig_name));
                    
            //     } else {
            //         path = source_path;
            //     }

            // // check if file hidden file with the same name with a .dir extension
            // // if so this contains the file name
            // } else if CryptFS::is_file(source_path.parent().unwrap().join(format!(".{}", source_path.file_name().unwrap().to_str().unwrap())).as_path()) {
            //     let dir_file = source_path.parent().unwrap().join(format!(".{}", source_path.file_name().unwrap().to_str().unwrap()));

                
            // } else {
            //     path = source_path;
            // }

            // let name: OsString = match path.file_name() {
            //     Some(name) => name.to_owned(),
            //     None => continue,
            // };

            // entries.push(DirectoryEntry {
            //     name: name,
            //     kind: if path.is_dir() { FileType::Directory } else { FileType::RegularFile }
            // });
        }
        
        // return Ok(entries);
        return Err(libc::ENOSYS);

    }

    fn releasedir(&self, _req: RequestInfo, _path: &Path, _fh: u64, _flags: u32) -> ResultEmpty {
        debug!("releasedir() called");
        
        let f = unsafe{ fs::File::from_raw_fd(_fh as RawFd) };
        drop(f);
        return Ok(());
    }

    fn fsyncdir(&self, _req: RequestInfo, _path: &Path, _fh: u64, _datasync: bool) -> ResultEmpty {
        debug!("fsyncdir() called");
        return Ok(());  // nothing to do
    }

    fn statfs(&self, _req: RequestInfo, _path: &Path) -> ResultStatfs {
        debug!("statfs() called");
        // TODO: implement
        return Err(libc::ENOSYS);
    }

    fn setxattr(&self, _req: RequestInfo, _path: &Path, _name: &OsStr, _value: &[u8], _flags: u32, _position: u32) -> ResultEmpty {
        debug!("setxattr() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn listxattr(&self, _req: RequestInfo, _path: &Path, _size: u32) -> ResultXattr {
        debug!("listxattr() called");
        // not implemented
        return Err(libc::ENOSYS);
    }

    fn getxattr(&self, _req: RequestInfo, _path: &Path, _name: &std::ffi::OsStr, _size: u32) -> ResultXattr {
        debug!("getxattr() called");
        // not implemented
        return Err(libc::ENOSYS);
    }

    fn removexattr(&self, _req: RequestInfo, _path: &Path, _name: &OsStr) -> ResultEmpty {
        debug!("removexattr() called");
        // read only filesystem
        return Err(libc::EROFS);
    }

    fn access(&self, _req: RequestInfo, _path: &Path, _mask: u32) -> ResultEmpty {
        debug!("access() called");
        // TODO: see if this is needed or if cloning the file permission is enough
        return Err(libc::ENOSYS)
    }

    fn create(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr, _mode: u32, _flags: u32) -> ResultCreate {
        debug!("create() called");
        // read only filesystem
        return Err(libc::EROFS);
    }
    

}
