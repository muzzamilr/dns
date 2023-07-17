use super::{byte_container::ByteContainer, errors::DnsErrors, query_type::QueryType};

#[derive(Clone, Debug)]
pub struct Question {
    name: String,
    qtype: QueryType,
}

impl Question {
    pub fn new(name: String, qtype: QueryType) -> Question {
        Question { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut ByteContainer) -> Result<(), DnsErrors> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }
}
