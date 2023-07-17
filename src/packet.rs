use super::{
    byte_container::ByteContainer, errors::DnsErrors, header::Header, query_type::QueryType,
    question::Question, record::Record,
};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub record: Vec<Record>,
    // authorities: Vec<Record>,
    // resources: Vec<Record>,
}

#[allow(dead_code)]
impl Packet {
    pub fn new() -> Packet {
        Packet {
            header: Header::create(),
            questions: Vec::new(),
            record: Vec::new(),
            // authorities: Vec::new(),
            // resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut ByteContainer) -> Result<Packet, DnsErrors> {
        let mut result = Packet::new();
        result.header.read(buffer);

        for _ in 0..result.header.questions {
            let question = Question::read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = Record::read(buffer)?;
            result.record.push(rec);
        }
        // for _ in 0..result.header.authoritative_entries {
        //     let rec = Record::read(buffer)?;
        //     result.authorities.push(rec);
        // }
        // for _ in 0..result.header.resource_entries {
        //     let rec = Record::read(buffer)?;
        //     result.resources.push(rec);
        // }

        Ok(result)
    }
}