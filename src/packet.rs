use super::{
    byte_container::ByteContainer, errors::DnsErrors, header::Header, question::Question,
    record::Record,
};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub record: Vec<Record>,
}

#[allow(dead_code)]
impl Packet {
    pub fn new() -> Packet {
        Packet {
            header: Header::new(),
            questions: Vec::new(),
            record: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut ByteContainer) -> Result<Packet, DnsErrors> {
        let header = Header::from_buffer(buffer)?;

        let mut result = Packet::new();
        result.header = header;

        for _ in 0..result.header.questions {
            let question = Question::from_buffer(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = Record::from_buffer(buffer)?;
            result.record.push(rec);
        }

        Ok(result)
    }

    pub fn to_buffer(&mut self, buffer: &mut ByteContainer) -> Result<(), DnsErrors> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.record.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.record {
            rec.write(buffer)?;
        }
        Ok(())
    }
}
