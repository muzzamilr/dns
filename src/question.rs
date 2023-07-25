use super::{byte_container::ByteContainer, errors::DnsErrors, query_type::QueryType};
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Question {
    name: String,
    qtype: QueryType,
}

impl Question {
    pub fn try_from(name: String, qtype: QueryType) -> Result<Question, DnsErrors> {
        Ok(Question { name, qtype })
    }
    pub fn from_buffer(buffer: &mut ByteContainer) -> Result<Question, DnsErrors> {
        let qname = buffer.read_qname()?;
        let qtype = QueryType::from_num(buffer.read_u16()?)?; // qtype
        let _ = buffer.read_u16()?; // class

        Ok(Question { name: qname, qtype })
    }

    pub fn write(&self, buffer: &mut ByteContainer) -> Result<(), DnsErrors> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}
