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

/// TODO: Change this into a struct
const AES_128_KEY_SIZE: usize = 16;
const AES_256_KEY_SIZE: usize = 32;
const AES_BLOCK_SIZE: usize = 16;
const MAC_SIZE: usize = (256 / 8) as usize;
const U64_SIZE: usize = (u64::BITS / 8) as usize;
const HEADER_SIZE: usize = AES_BLOCK_SIZE * 22;

/// Header of encrypted files
/// Stores metadata of original file
struct CryptFSHeader {
    /// MAC for file header, this includes the `data_mac`
    pub header_mac: [u8; MAC_SIZE],
    /// MAC for file data
    pub data_mac: [u8; MAC_SIZE],
    /// This is the start of encryption, it will be corrupted during decryption and discarded
    empty: [u8; AES_BLOCK_SIZE],
    /// Original file size
    pub file_size: u64,
    /// Original file name
    pub file_name: [u8; 256],
    /// Padding to make the header a multiple of AES_BLOCK_SIZE
    zero: [u8; 8],
}

impl CryptFSHeader {
    /// Creates a new header
    /// Initializes all fields to zero
    fn new() -> Self {
        return CryptFSHeader {
            header_mac: [0; MAC_SIZE],
            data_mac: [0; MAC_SIZE],
            empty: [0; AES_BLOCK_SIZE],
            file_size: 0,
            file_name: [0; 256],
            zero: [0; 8],
        };
    }

    /// Packs the header into a vector of bytes
    /// Header MAC MSB is MSB of the returned vector
    fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);
        buf.extend_from_slice(&self.header_mac);
        buf.extend_from_slice(&self.data_mac);
        buf.extend_from_slice(&self.empty);
        buf.extend_from_slice(&self.file_size.to_be_bytes());
        buf.extend_from_slice(&self.file_name);
        buf.extend_from_slice(&self.zero);
        assert!(buf.len() == HEADER_SIZE, "Header size is not correct");
        return buf;
    }

    fn unpack(&mut self, data: &[u8]) {
        self.header_mac.copy_from_slice(&data[0..AES_BLOCK_SIZE*2]);
        self.data_mac.copy_from_slice(&data[AES_BLOCK_SIZE*2..AES_BLOCK_SIZE*4]);
        self.empty.copy_from_slice(&data[AES_BLOCK_SIZE*4..AES_BLOCK_SIZE*5]);
        self.file_size = u64::from_be_bytes(data[AES_BLOCK_SIZE*5..AES_BLOCK_SIZE*5+U64_SIZE].try_into().unwrap());
        self.file_name.copy_from_slice(&data[AES_BLOCK_SIZE*5+U64_SIZE..AES_BLOCK_SIZE*21+U64_SIZE]);
        self.zero.copy_from_slice(&data[AES_BLOCK_SIZE*21+U64_SIZE..HEADER_SIZE]);
    }
    
}


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

#[derive(Debug, Clone)]
pub struct CryptFSOptions {
    pub mode: CryptFSMode,
    pub hide_file_names: bool,
    pub compress_files: bool,
    pub key_size: usize,
    pub readwrite: bool,
}

impl Default for CryptFSOptions {
    fn default() -> Self {
        return CryptFSOptions {
            mode: CryptFSMode::Auto,
            hide_file_names: true,
            compress_files: false,
            key_size: AES_256_KEY_SIZE,
            readwrite: false,
        };
    }
}


pub struct CryptFS   {
    cipher: Cipher,
    key: Vec<u8>,
    src_dir: PathBuf,
    options: CryptFSOptions,
}

/// TODO: Add option to encrypt/decrypt file and directory names - adding them to the header, new filename = hash(filename)
/// IDEA: Add option to use CFB and CTR modes for encryption/decryption (CTR can be parallelized)
/// IDEA: Add option for readwrite mode
/// IDEA: Create config file to store configuration options
/// IDEA: Protect source files by locking them using atomic file locking
/// IDEA: Add option of compressing files before encrypting them
impl CryptFS {

    /// Creates a new CryptFS object
    /// if the key is 16 bytes, AES-128-CBC is used
    /// if the key is 32 bytes, AES-256-CBC is used
    /// 
    /// # Arguments
    /// * `key` - Key to use for encryption/decryption
    /// * `src_dir_path` - Path to the directory that the fuse layer will source files from
    /// * `options` - See [`CryptFSOptions`]
    /// 
    /// # Panics
    /// Panics if the directory does not exist.
    /// Panics if the key size does not equal 128 or 256 
    pub fn new<S: AsRef<str>>(key: S, src_dir_path: S, options: Option<CryptFSOptions>) -> Self {

        let key = key.as_ref();
        let src_dir_path = src_dir_path.as_ref();
        let options = options.unwrap_or_default();

        // check directory exists
        if !fs::metadata(src_dir_path).is_ok() {
            error!("Directory does not exist");
            panic!();
        }

        let src_dir = PathBuf::from(src_dir_path).canonicalize().unwrap();

        let key_hash = &hash(MessageDigest::sha256(), key.as_bytes()).unwrap()[..];

        let cipher: Cipher;
        let crypt_key: Vec<u8>;

        match options.key_size {
            AES_128_KEY_SIZE => {   
                cipher = Cipher::aes_128_cbc();
                crypt_key = key_hash[0..AES_128_KEY_SIZE].to_vec();
            }
            AES_256_KEY_SIZE => {
                cipher = Cipher::aes_256_cbc();
                crypt_key = key_hash[0..AES_256_KEY_SIZE].to_vec();
            }
            _ => panic!("Only 128 and 256 encryption is supported"),
        };
    
        return CryptFS {
            cipher: cipher,
            key: crypt_key,
            src_dir: src_dir,
            options: options,
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
        let mut c = Crypter::new(self.cipher, mode, &self.key, iv)?;
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


    /// Decrypts the header of an encrypted file
    /// This will check if the MAC is valid return the header
    /// 
    /// # Arguments
    /// * `data` - Header to decrypt, must be at least [`HEADER_SIZE`] bytes
    /// 
    /// # Returns
    /// A [`CryptFSHeader`] struct containing the decrypted header
    /// 
    /// # Errors
    /// [`CryptFSError::MacMismatch`] - If the MAC does not match the computed MAC
    /// 
    /// # Panics
    /// If data is less than [`HEADER_SIZE`] bytes
    fn decrypt_header(&self, data: &[u8]) -> Result<CryptFSHeader, CryptFSError> {
        let mut header = CryptFSHeader::new();

        let header_mac = &data[0..MAC_SIZE];
        let computed_mac = self.compute_sha256_hmac(&data[MAC_SIZE*1..HEADER_SIZE])?;

        for i in 0..MAC_SIZE {
            if header_mac[i] != computed_mac[i] {
                return Err(CryptFSError::MacMismatch);
            }
        }

        let mut header_data = Vec::from(&data[0..MAC_SIZE*2]);
        header_data.append(&mut self._decrypt(&data[MAC_SIZE*2..HEADER_SIZE], None)?);
        header.unpack(&header_data);
        
        return Ok(header);
    }

    /// Reads a file into a padded buffer of bytes
    /// The size of the buffer is determined by the CryptMode
    /// 
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
        let mut mac = HmacSha256::new_from_slice(&self.key)?;
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
                    let mut header_buf = vec![0; HEADER_SIZE];
                    file.read_exact_at(&mut header_buf, 0)?;
                    let header = self.decrypt_header(&header_buf)?;
                    return Ok(header.file_size);
                }
            }
        }

        return Ok(new_size);
    }

    /// Encrypts file data with a header
    /// 
    /// # Arguments
    /// * `file` - Data to encrypt, must be a vector generated by `crypt_read_file`
    /// * `file_name` - Original name of the file
    /// 
    /// # Returns
    /// Encrypted copy of the file data with a [`CryptFSHeader`] prepended
    /// 
    /// # Errors
    /// [`CryptFSError`]
    fn encrypt_file(&self, file: &fs::File, file_name: &[u8]) -> Result<Vec<u8>, CryptFSError> {

        // Get data from file with extra room for header and padding
        let mut data = self.crypt_read_file(file, CryptMode::Encrypt)?;

        // Add all information to header except the data MAC and header MAC
        let mut header = CryptFSHeader::new();
        header.file_size = file.metadata()?.len();
        header.file_name[..file_name.len()].copy_from_slice(file_name);
        data[0..HEADER_SIZE].copy_from_slice(&header.pack());

        // Generate random IV and encrypt data starting after the data MAC
        // A hash is used to generate the IV for two reasons:
        // 1. It is repeatable, so the IV does not need to be stored
        // 2. The IV will change if any data is changed
        let iv = &hash(MessageDigest::md5(), &data[HEADER_SIZE..])?[..];
        let mut enc_buf = Vec::from(&data[0..MAC_SIZE*2]);
        enc_buf.append(&mut self._encrypt(&data[MAC_SIZE*2..], Some(&iv))?);
        

        // Add the data MAC to the header, this protects from:
        // - Data corruption
        // - Data from padding oracle attacks
        let data_mac = self.compute_sha256_hmac(&enc_buf[HEADER_SIZE..])?;
        enc_buf[MAC_SIZE..MAC_SIZE*2].copy_from_slice(&data_mac);

        // Add the header MAC to the header, this protects from:
        // - Header corruption
        // - Header from padding oracle attacks
        // The reason for using two MACs is the header can be decrypted without reading the entire file
        // while protecting the data from padding oracle attacks
        // This is needed when listing contents of a directory
        let header_mac = self.compute_sha256_hmac(&enc_buf[MAC_SIZE..HEADER_SIZE])?;
        enc_buf[0..MAC_SIZE].copy_from_slice(&header_mac);

        return Ok(enc_buf);
        
    }

    /// Decrypts file data
    /// Data to be decrypted must have a header
    /// 
    /// # Arguments
    /// * `file` - Size to decrypt, size must be at least [`HEADER_SIZE`]
    /// 
    /// # Returns
    /// A vector of bytes containing the decrypted data without the header or padding
    /// 
    /// # Errors
    /// [`CryptFSError`]
    /// 
    /// # Panics
    /// If the file size is less than [`HEADER_SIZE`]
    fn decrypt_file(&self, file: &fs::File) -> Result<(Vec<u8>, CryptFSHeader), CryptFSError> {

        // Get data and check header MAC
        let data = self.crypt_read_file(file, CryptMode::Decrypt)?;
        let header = self.decrypt_header(&data)?;
        let computed_mac = self.compute_sha256_hmac(&data[HEADER_SIZE..])?;

        // Check data MAC
        for i in 0..MAC_SIZE {
            if header.data_mac[i] != computed_mac[i] {
                return Err(CryptFSError::MacMismatch);
            }
        }

        // Decrypt the data using last 16 bytes of the header as the IV
        let mut dec_buf = self._decrypt(&data[HEADER_SIZE..], Some(&data[HEADER_SIZE-AES_BLOCK_SIZE..HEADER_SIZE]))?;
        dec_buf.truncate(header.file_size as usize); // remove padding

        return Ok((dec_buf, header));

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

