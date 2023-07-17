#[allow(dead_code)]
#[derive(Debug)]
pub enum DnsErrors {
    InsufficientBytesForHeader,
    InsufficientBytesForQuestion,
    InsufficientBytesForRecord,
    ByteContainerError,
}
