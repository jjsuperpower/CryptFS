use std::path::{Path, PathBuf};
use std::os::unix::prelude::FileExt;
use std::fs;
use openssl;
use openssl::symm::{Cipher, Crypter, Mode as CryptoMode};
use openssl::hash::{hash, MessageDigest};
use sha2::Sha256;
use hmac::{Hmac, Mac};

#[allow(unused_imports)]
use log::{debug, info, error};

mod fuse;
mod error;
use error::CryptFSError;

type HmacSha256 = Hmac<Sha256>;


/* Constants used for encryption/decryption
   Header is composed of:
   - MAC (SHA256 digest)
   - Original file size (8 bytes or u64 big endian)
   - 16 bytes of padding, will be corrupted during decryption
   - File data
   - Padding to make file size a multiple of AES block size
*/
/// TODO: Change this into a struct
const AES_128_KEY_SIZE: usize = 16;
const AES_256_KEY_SIZE: usize = 32;
const AES_BLOCK_SIZE: usize = 16;
const HEADER_SIZE: usize = AES_BLOCK_SIZE*4;            // must be multiple of AES_BLOCK_SIZE, else first block will be corrupted during decryption
const MAC_OFFSET: usize = 0;
const MAC_SIZE: usize = AES_BLOCK_SIZE*2;               // size of a SHA256 digest
const ORIG_FSIZE_OFFSET: usize = MAC_OFFSET + MAC_SIZE; // offset of original file size in header
const ORIG_FSIZE_SIZE: usize = 8;                       // size of original file size in header

/// Not to be confused with [`CryptoMode`] or [`CryptFSMode`]
/// 
/// This is used by internal functions to determine whether to encrypt or decrypt
#[derive(Debug, Clone, Copy)]
enum CryptMode {
    Encrypt = 0,
    Decrypt = 1,
}


/// Controls how the filesystem will encrypt/decrypt files
#[derive(Debug, Clone, Copy)]
pub enum CryptFSMode {
    /// Will only encrypt files, will ignore files with a .cryptfs extension
    EncryptOnly,
    /// Will only decrypt files, will ignore files without a .cryptfs extension
    DecryptOnly,
    /// Will encrypt files without a .cryptfs extension and decrypt files with a .cryptfs extension
    Auto,
}

pub struct CryptFS   {
    cipher: Cipher,
    key: String,
    src_dir: PathBuf,
    mode: CryptFSMode,
    
}

/// TODO: Add option to encrypt/decrypt file and directory names - adding them to the header, new filename = hash(filename)
/// TODO: Add option to use CFB and CTR modes for encryption/decryption (CTR can be parallelized)
/// TODO: Add option for readwrite mode
/// TODO: Generate encryption key, encrypt it with a password, store it in a file
/// TODO: Create config file to store configuration options
/// TODO: Protect source files by locking them using atomic file locking
/// TODO: Add option of compressing files before encrypting them
impl CryptFS {

    /// Creates a new CryptFS object
    /// if the key is 16 bytes, AES-128-CBC is used
    /// if the key is 32 bytes, AES-256-CBC is used
    /// 
    /// # Arguments
    /// * `key` - Key to use for encryption/decryption
    /// * `src_dir_path` - Path to the directory that the fuse layer will source files from
    /// * `mode` - Weather to encrypt, decrypt, or both. Defaults to both
    /// 
    /// # Panics
    /// Panics if the directory does not exist.
    /// Panics if the key is not 16 or 32 bytes.
    pub fn new(key: String, src_dir_path: String, mode: Option<CryptFSMode>) -> Self {
        // check directory exists
        if !fs::metadata(src_dir_path.clone()).is_ok() {
            error!("Directory does not exist");
            panic!();
        }

        let src_dir = PathBuf::from(src_dir_path).canonicalize().unwrap();

        let cipher: Cipher;
        if key.as_bytes().len() == AES_128_KEY_SIZE {
            cipher = Cipher::aes_128_cbc();
        } else if key.as_bytes().len() == AES_256_KEY_SIZE {
            cipher = Cipher::aes_256_cbc();
        } else {
            panic!("Invalid key size");
        }

        let mode = match mode {
            Some(mode) => mode,
            None => CryptFSMode::Auto,
        };
    
        return CryptFS {
            cipher: cipher,
            key: key,
            src_dir: src_dir,
            mode: mode,
        };
    }

    /// Controls libssl's Crypter Implementation
    /// 
    /// This has padding disabled, so data must be a multiple of the block size
    /// # Arguments
    /// * `data` - Data to encrypt/decrypt
    /// * `iv` - Initialization vector
    /// * `mode` - Whether to encrypt or decrypt
    /// 
    /// # Returns
    /// A vector of bytes containing the encrypted/decrypted data
    /// 
    /// # Errors
    /// [`CryptFSError::InternalError`] - If there is an internal error.
    /// This *should* never happen
    fn _crypter(&self, data: &[u8], iv:Option<&[u8]>, mode: CryptoMode) -> Result<Vec<u8>, CryptFSError> {
        let mut c = Crypter::new(self.cipher, mode,self.key.as_bytes(), iv)?;
        c.pad(false);
        let mut out = vec![0; data.len() + self.cipher.block_size()];
        let count =c.update(data, &mut out)?;
        let rest = c.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        return Ok(out);
    }

    /// Encrypts data using the key and iv provided
    /// Calls [`CryptFS::_crypter`] with [`CryptoMode::Encrypt`] as the mode
    fn _encrypt(&self, data: &[u8], iv:Option<&[u8]>) -> Result<Vec<u8>, CryptFSError> {
        self._crypter(data, iv, CryptoMode::Encrypt)
    }

    /// Decrypts data using the key and iv provided
    /// Calls [`CryptFS::_crypter`] with [`CryptoMode::Decrypt`] as the mode
    fn _decrypt(&self, data: &[u8], iv:Option<&[u8]>) -> Result<Vec<u8>, CryptFSError> {
        self._crypter(data, iv, CryptoMode::Decrypt)
    }

    /// Reads a file into a padded buffer of bytes
    /// In order to reduce copying vectors this function is used to read the file into a buffer
    /// that the encryption/decryption functions can use directly
    /// # Arguments
    /// * `file` - File to read
    /// * `mode` - Weather the file will be encrypted or decrypted
    /// 
    /// # Returns
    /// A vector of bytes containing the file data and padding (if encrypting)
    /// 
    /// # Errors
    /// * [`CryptFSError::InvalidPath`] - If the source file does cannot be accessed or does not exist
    /// * [`CryptFSError::InvalidFileSize`] - If the source file size is less than [`HEADER_SIZE`]
    /// * [`CryptFSError::FileReadError`] - If the source file cannot be read
    fn crypt_read_file(&self, file: &fs::File, mode: CryptMode) -> Result<Vec<u8>, CryptFSError> {
        let file_size = file.metadata()?.len();

        match mode {
            CryptMode::Encrypt => {
                let buf_size = self.get_crypt_read_size(file, CryptMode::Encrypt)?;
                let mut buf = vec![0; buf_size as usize];
                file.read_exact_at(&mut buf[HEADER_SIZE..HEADER_SIZE+file_size as usize], 0)?;
                Ok(buf)
            },
            CryptMode::Decrypt => {
                let mut buf = vec![0; file_size as usize];
                file.read_exact_at(&mut buf, 0)?;
                Ok(buf)
            }
        }
    }

    /// Simple wrapper around compute_sha256_hmac
    /// # Arguments
    /// * `data` - Data to compute the hmac of
    /// 
    /// # Returns
    /// A vector of bytes containing the hmac
    /// 
    /// # Errors
    /// [`CryptFSError::InternalError`] - If the hmac cannot be computed
    fn compute_sha256_hmac(&self, data: &[u8]) -> Result<Vec<u8>, CryptFSError> {
        let mut mac = HmacSha256::new_from_slice(self.key.as_bytes())?;
        mac.update(data);
        let mac = mac.finalize().into_bytes();
        return Ok(mac.to_vec());
    }
    
    /// Calculates expected size of encrypted/decrypted file
    /// This can be less or greater than the original file size depending on the mode of cryption
    /// If the file is zero bytes, the size will be zero bytes, this empty files are not encrypted/decrypted
    /// 
    /// # Arguments
    /// `file` - File to calculate the size of
    /// For encryption, all that is needed is the file size.
    /// For decryption, the original file size is stored in the header and must be read
    /// 
    /// Ecrypted file size = HEADER_SIZE as u64 + file_size padded to multiple of AES_BLOCK_SIZE
    /// Decrypted file size = original (source file) size
    /// 
    /// # Returns
    /// The expected size of the encrypted/decrypted file
    /// 
    /// # Errors
    /// `CryptFSError::InvalidPath` - If the file cannot be accessed
    /// `CryptFSError::InvalidFileSize` - If the file size is less than [`HEADER_SIZE`](constant.HEADER_SIZE.html)
    fn get_crypt_read_size(&self, file: &fs::File, mode: CryptMode) -> Result<u64, CryptFSError> {
        let mut new_size : u64 = 0;
        let file_size = file.metadata()?.len();

        // there is no need to encrypt/decrypt an empty file
        if file_size == 0 {
            return Ok(new_size);
        }

        match mode {
            CryptMode::Encrypt => {
                let aes_padding = AES_BLOCK_SIZE as u64 - (file_size % AES_BLOCK_SIZE as u64);
                new_size = HEADER_SIZE as u64 + file_size + aes_padding;
            },
            CryptMode::Decrypt => {
                if file_size < HEADER_SIZE as u64 {
                    return Err(CryptFSError::InvalidFileSize);
                } else {
                    let mut size: [u8; 8] = [0; 8];
                    fs::File::read_exact_at(&file, &mut size, ORIG_FSIZE_OFFSET as u64)?;
                    new_size = u64::from_be_bytes(size);
                }
            }
        }

        return Ok(new_size);
    }

    /// Encrypts file data with a header
    /// The header is composed of:
    /// * MAC (SHA256 digest)
    /// * Original file size (8 bytes or u64 big endian)
    /// * 16 bytes of padding, will be corrupted during decryption
    /// * File data
    /// * Padding (if file size is not a multiple of AES block size)
    /// 
    /// # Arguments
    /// * `data` - Data to encrypt, must be a vector generated by `crypt_read_file`
    /// * `orig_size` - Original size of the file
    /// 
    /// # Returns
    /// Encrypted copy of the file data with a header prepended
    /// 
    /// # Errors
    /// [`CryptFSError::InternalError`] - If there is an error in encrypting the data
    /// 
    /// # Panics
    /// If the buffer is not the correct size
    fn encrypt(&self, data: &Vec<u8>, orig_size: u64) -> Result<Vec<u8>, CryptFSError> {

        // get iv from file hash, this makes it repeatable for the same file
        let iv = &hash(MessageDigest::md5(), &data[HEADER_SIZE..])?[..];

        // encrypt the file
        let mut enc_buf = self._encrypt(data.as_slice(), Some(&iv))?;

        // add size of original file to header
        enc_buf[ORIG_FSIZE_OFFSET..ORIG_FSIZE_OFFSET+ORIG_FSIZE_SIZE].copy_from_slice(&orig_size.to_be_bytes());

        // compute mac, include original file size
        let mac = self.compute_sha256_hmac(&enc_buf[ORIG_FSIZE_OFFSET..])?;

        // add mac to header, 
        enc_buf[MAC_OFFSET..MAC_OFFSET+MAC_SIZE].copy_from_slice(&mac.as_slice());

        return Ok(enc_buf);
        
    }

    /// Decrypts file data
    /// Data to be decrypted must have a header
    /// 
    /// # Arguments
    /// * `data` - Data to decrypt, size must be at least [`HEADER_SIZE`]
    /// 
    /// # Returns
    /// A vector of bytes containing the decrypted data without the header or padding
    /// 
    /// # Errors
    /// [`CryptFSError::MacMismatch`] - If the MAC does not match the computed MAC
    /// [`CryptFSError::InternalError`] - If there is an error in decrypting the data
    /// 
    /// # Panics
    /// If the buffer is not the correct size
    fn decrypt(&self, data: &Vec<u8>) -> Result<Vec<u8>, CryptFSError> {
        let file_mac = &data[MAC_OFFSET..MAC_OFFSET+MAC_SIZE];
        let computed_mac = self.compute_sha256_hmac(&data[ORIG_FSIZE_OFFSET..])?;

        // TODO: Add more explicit error types
        for i in 0..MAC_SIZE {
            if file_mac[i] != computed_mac[i] {
                return Err(CryptFSError::MacMismatch);
            }
        }

        // get original file size from header
        let orig_file_size = u64::from_be_bytes(data[ORIG_FSIZE_OFFSET..ORIG_FSIZE_OFFSET+ORIG_FSIZE_SIZE].try_into().unwrap());

        let dec_buf = self._decrypt(&mut data.as_slice(), None)?;

        // return decrypted data without the header or padding
        return Ok(dec_buf[HEADER_SIZE..HEADER_SIZE + orig_file_size as usize].to_vec());

    }

    /// Translates file data using the mode specified
    /// Calls encrypt or decrypt depending on the mode
    fn crypt_translate(&self, file: &fs::File, mode: CryptMode) -> Result<Vec<u8>, CryptFSError> {
        let file_data = self.crypt_read_file(file, mode)?;
        let orig_size = file.metadata().unwrap().len();

        return match mode {
            CryptMode::Encrypt => {
                self.encrypt(&file_data, orig_size)
            }
            CryptMode::Decrypt => {
                if (orig_size < HEADER_SIZE as u64) && (orig_size != 0) { // if the file is too small we should not try to decrypt it
                    return Err(CryptFSError::InvalidFileSize);
                }
                self.decrypt(&file_data)
            },
        };
    }

    /// Logs the error message to the console
    /// 
    /// # Arguments
    /// `CryptFSError` - Error message to log
    /// `Option<&Path>` - Path of the file that caused the error
    /// 
    fn log_error(&self, err: CryptFSError, path: Option<&Path>) {

        let show_as_err = || {
            if let Some(path) = path {
                error!("'{}' for '{}'", err, path.display());
            } else {
                error!("'{}'", err);
            }
        };

        let show_as_info = || {
            if let Some(path) = path {
                info!("'{}' for '{}'", err, path.display());
            } else {
                info!("'{}'", err);
            }
        };

        match &err {
            CryptFSError::InternalError(anyhow_err) => {
                show_as_err();

                let stack_trace = anyhow_err.backtrace();
                if std::backtrace::Backtrace::status(stack_trace) == std::backtrace::BacktraceStatus::Disabled {
                    info!("-----------------------------------------------------");
                    info!("  To view stack trace, run with RUST_BACKTRACE=full  ");
                    info!("-----------------------------------------------------");
                } else {
                    println!("Start of stack trace");
                    println!("-------------------------------");
                    println!("{}", stack_trace.to_string());
                    println!("-------------------------------");
                    println!("End of stack trace");
                }
            }
            CryptFSError::InvalidPath => {
                show_as_info();
            }
            _ => {
                show_as_err();
            },
        }
    }


}

