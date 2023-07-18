use super::{byte_container::ByteContainer, errors::DnsErrors, query_type::QueryType};

#[derive(Clone, Debug)]
pub struct Question {
    name: String,
    qtype: QueryType,
}

impl Question {
    pub fn from_buffer(buffer: &mut ByteContainer) -> Result<Question, DnsErrors> {
        let qname = buffer.read_qname()?;
        let qtype = QueryType::from_num(buffer.read_u16()?)?; // qtype
        let _ = buffer.read_u16()?; // class

        Ok(Question { name: qname, qtype })
    }
}
