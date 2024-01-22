use thiserror::Error;
use anyhow;
use std::io;

/// Represents various errors that can occur during encryption/decryption
/// 
/// These give a general idea of what went wrong, but are not very specific.
/// They do not capture internal errors of the openssl library or other libraries
#[derive(Debug, Error)]
pub enum CryptFSError {
    /// Pray you do not see this error
    /// If this happens, get ready to debug...
    #[error(transparent)]
    InternalError(#[from] anyhow::Error),
    /// Encryption/Decryption key is not correct
    #[error("Crypt key is invalid")]
    InvalidKey, // TODO: Add a way to detect if the key is invalid
    /// Requested path (file) could not be accessed
    /// See [`get_source_path`](fuse/fn.get_source_path.html) for more details
    #[error("Path is does not exist")]
    InvalidPath,
    /// Requested path is not a regular file or directory
    /// For security reasons, this filesystem will not follow symlinks, or other special files
    #[error("Path is not a regular file or directory")]
    IrregularFile,
    /// All encrypted files are larger than the original file (except for empty files)
    /// This is because a header is prepended to the file to give information about the original file
    /// If the file is non-zero in size, but less than [`HEADER_SIZE`], this error will be thrown
    #[error("File size is invalid")]
    InvalidFileSize,
    /// File cannot be read
    /// This is usually caused by a permissions error for the source file
    #[error("File cannot be read")]
    FileReadError,
    /// When decrypting a file, the MAC is checked before decrypting the file
    /// This is done to detect a corrupted file and for security reasons
    #[error("MAC mismatch, file possibly corrupted?")]
    MacMismatch,
}

impl From<io::Error> for CryptFSError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => CryptFSError::InvalidPath,
            io::ErrorKind::PermissionDenied => CryptFSError::FileReadError,
            _ => CryptFSError::InternalError(anyhow::Error::from(err)),
        }
    }
}

impl From<openssl::error::ErrorStack> for CryptFSError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        CryptFSError::InternalError(anyhow::Error::from(err))
    }
}

impl From<hmac::digest::crypto_common::InvalidLength> for CryptFSError {
    fn from(err: hmac::digest::crypto_common::InvalidLength) -> Self {
        CryptFSError::InternalError(anyhow::Error::from(err))
    }
}