#[allow(dead_code)]
use std::fmt::Display;
#[derive(Debug)]
pub enum DnsErrors {
    InsufficientBytesForHeader,
    InsufficientBytesForQuestion,
    InsufficientBytesForRecord,
    ByteContainerError,
    IndexOutOfBound,
    QueryTypeMismatch,
    ResponseCodeError,
}

impl std::error::Error for DnsErrors {}

impl Display for DnsErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
