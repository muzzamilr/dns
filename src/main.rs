use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};

// const DNS_IP: &str = "8.8.8.8"; // Public DNS Server
// const PORT: u16 = 53;
// const RES_BUFF: usize = 1024; // Size for the response buffer
// const DNS_SERVER: (&str, u16) = (DNS_IP, PORT);

// fn set_bit(num: u8), idx: u8) {
//
// }
//
// fn is_bit_set(num, u8, idx: u8) -> bool {
//
// }
//

#[derive(Debug)]
enum DnsErrors {
    InsufficientBytesForHeader,
    InsufficientBytesForQuestion,
    InsufficientBytesForRecord,
    ByteContainerError,
}

#[derive(Debug)]
struct ByteContainer {
    list: [u8; 512],
    pos: usize,
}

impl ByteContainer {
    fn new() -> ByteContainer {
        ByteContainer {
            list: [0; 512],
            pos: 0,
        }
    }
    fn position(&self) -> usize {
        self.pos
    }
    fn skip(&mut self, steps: usize) -> Result<(), DnsErrors> {
        self.pos += steps;
        Ok(())
    }

    fn change_position(&mut self, position: usize) -> Result<(), DnsErrors> {
        self.pos = position;
        Ok(())
    }

    fn read(&mut self) -> Result<u8, DnsErrors> {
        if self.pos >= 512 {
            return Err(DnsErrors::ByteContainerError);
        }
        let val = self.list[self.pos];
        self.pos += 1;
        Ok(val)
    }

    fn read_u16(&mut self) -> Result<u16, DnsErrors> {
        let val = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(val)
    }

    fn read_u32(&mut self) -> Result<u32, DnsErrors> {
        let val = ((self.read_u16()? as u32) << 16) | (self.read_u16()? as u32);
        Ok(val)
    }

    fn get(&mut self, pos: usize) -> Result<u8, DnsErrors> {
        if pos >= 512 {
            return Err(DnsErrors::ByteContainerError);
        }
        Ok(self.list[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], DnsErrors> {
        if start + len >= 512 {
            return Err(DnsErrors::ByteContainerError);
        }
        Ok(&self.list[start..start + len as usize])
    }

    fn read_qname(&mut self, outstr: &mut String) -> Result<(), DnsErrors> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.position();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(DnsErrors::ByteContainerError);
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.change_position(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.change_position(pos)?;
        }

        Ok(())
    }
}

// fn sequence<T, E: std::fmt::Debug + std::fmt::Display>(
//     list: Vec<Result<T, E>>,
// ) -> Result<Vec<T>, E> {
//     let mut res = Vec::new();
//
//     for r in list {
//         // res.push(r?);
//         match r {
//             Err(e) => return Err(e),
//             Ok(val) => {
//                 res.push(val);
//             }
//         }
//     }
//
//     Ok(res)
// }

// enum Errors {
//     InsufficientBytesForHeader,
//     InsufficientBytesForDomain,
// }

// #[derive(Debug)]
// struct InsufficientBytesForHeader;

// impl std::fmt::Display for DnsErrors {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "Insufficient bytes for the header")
//     }
// }
// impl std::error::Error for DnsErrors {}
//
// struct HeaderBytes([u8; 12]);
//
// impl TryFrom<&Vec<u8>> for HeaderBytes {
//     type Error = DnsErrors;
//
//     fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
//         let bytes = value.iter().take(12).collect::<Vec<_>>();
//
//         if bytes.len() != 12 {
//             Err(DnsErrors::InsufficientBytesForHeader)
//         } else {
//             let mut res = [0; 12];
//
//             bytes.iter().zip(0..12).for_each(|(&&val, idx)| {
//                 res[idx] = val;
//             });
//
//             Ok(HeaderBytes(res))
//         }
//     }
// }
//
// impl HeaderBytes {
//     fn get_id(&self) -> u16 {
//         let id: u16 = (self.0[0] as u16) << 8 | self.0[1] as u16;
//         id
//     }
//     fn get_query_response(&self) -> bool {
//         let tmp_byte = self.0[2];
//         let mask = 0x80; // -> binary(10000000)
//         let masked_value = tmp_byte & mask;
//
//         masked_value > 0
//     }
//     fn get_opcode(&self) -> u8 {
//         let tmp = self.0[2];
//         let rt_sf = tmp >> 3;
//         // let lt_sf = rt_sf << 1;
//         let mask = 0x0f;
//         let opcode = rt_sf & mask;
//         opcode
//     }
//     fn get_auth_ans(&self) -> bool {
//         let tmp = self.0[2];
//         let mask = 0x4;
//         let masked_value = tmp & mask;
//         masked_value > 0
//     }
//     fn get_tc_msg(&self) -> bool {
//         let tmp = self.0[2];
//         let mask = 0x2;
//         let masked_value = tmp & mask;
//         masked_value > 0
//     }
//     fn get_recursion_desired(&self) -> bool {
//         let tmp = self.0[2];
//         let mask = 0x1;
//         let masked_value = tmp & mask;
//         masked_value > 0
//     }
//     fn get_recursion_available(&self) -> bool {
//         let tmp = self.0[3];
//         let mask = 0x80;
//         let masked_value = tmp & mask;
//         masked_value > 0
//     }
//     fn get_reserved(&self) -> u8 {
//         let tmp = self.0[3];
//         let rt_sf = tmp >> 4;
//         // let lt_sf = rt_sf << 4;
//         let mask = 0x7;
//         let reserved = rt_sf & mask;
//         reserved
//     }
//     fn get_response_code(&self) -> u8 {
//         let tmp = self.0[3];
//         // let rt_sf = tmp >> 4;
//         // let lt_sf = tmp << 4;
//         // lt_sf
//         let mask = 0x0f;
//         let response_code = tmp & mask;
//         response_code
//     }
//     fn get_question_count(&self) -> u16 {
//         let qd: u16 = (self.0[4] as u16) << 8 | self.0[5] as u16;
//         qd
//     }
//     fn get_answer_count(&self) -> u16 {
//         let an: u16 = (self.0[6] as u16) << 8 | self.0[7] as u16;
//         an
//     }
//     fn get_authority_count(&self) -> u16 {
//         let ns: u16 = (self.0[8] as u16) << 8 | self.0[9] as u16;
//         ns
//     }
//     fn get_additional_count(&self) -> u16 {
//         let ar: u16 = (self.0[10] as u16) << 8 | self.0[11] as u16;
//         ar
//     }
// }

// #[derive(Debug)]
// struct Question(Vec<u8>);
// #[derive(Debug)]
// struct InsufficientBytesForQuestion;

// impl std::fmt::Display for InsufficientBytesForQuestion {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "Insufficient bytes for the question")
//     }
// }
// impl std::error::Error for InsufficientBytesForHeader {}
// impl TryFrom<&Vec<u8>> for Question {
//     type Error = DnsErrors;
//
//     fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
//         let length = value[12];
//         let mut domain = Vec::new();
//         let count = 13 as usize;
//         let mut question = Vec::new();
//         if length == 0 {
//             Err(DnsErrors::InsufficientBytesForQuestion)
//         } else {
//             let mut i = 0;
//             while value[count + i] != 0 {
//                 domain.push(value[count + i]);
//                 question.push(value[count + i]);
//                 i += 1;
//             }
//             for x in count + domain.len()..count + domain.len() + 5 {
//                 question.push(value[x]);
//             }
//
//             Ok(Question(question))
//         }
//     }
// }
//
// impl Question {
//     fn get_domain(&self) -> Vec<u8> {
//         let mut domain = Vec::new();
//         let mut n = 0;
//         while self.0[n] != 0 {
//             domain.push(self.0[n]);
//             n += 1;
//         }
//         domain
//     }
//     fn get_type(&self) -> u16 {
//         let domain = self.get_domain();
//         let first: u8 = self.0[domain.len() + 1];
//         let second: u8 = self.0[domain.len() + 2];
//         let q_type: u16 = (first as u16) << 8 | second as u16;
//         q_type
//     }
//     fn get_class(&self) -> u16 {
//         let domain = self.get_domain();
//         let first: u8 = self.0[domain.len() + 3];
//         let second: u8 = self.0[domain.len() + 4];
//         let class: u16 = (first as u16) << 8 | second as u16;
//         class
//     }
// }

// #[derive(Debug)]
// struct RecordBytes(Vec<u8>);
//
// impl TryFrom<&Vec<u8>> for RecordBytes {
//     type Error = DnsErrors;
//
//     fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
//         let length = value[12];
//         let mut domain = Vec::new();
//         let count = 13 as usize;
//         let mut record = Vec::new();
//         if length == 0 {
//             Err(DnsErrors::InsufficientBytesForRecord)
//         } else {
//             let mut i = 0;
//             while value[count + i] != 0 {
//                 domain.push(value[count + i]);
//                 record.push(value[count + i]);
//                 i += 1;
//             }
//
//             // for x in count + domain.len()..count + domain.len() + 5 {
//             //     record.push(value[x]);
//             // }
//
//             for x in &value[count + domain.len()..] {
//                 record.push(x.clone())
//             }
//             Ok(RecordBytes(record))
//         }
//     }
// }
//
// impl RecordBytes {
//     fn get_domain(&self) -> Vec<u8> {
//         let mut domain = Vec::new();
//         let mut n = 0;
//         while self.0[n] != 0 {
//             domain.push(self.0[n]);
//             n += 1;
//         }
//         domain
//     }
//     fn get_type(&self) -> u16 {
//         let domain = self.get_domain();
//         let first: u8 = self.0[domain.len() + 1];
//         let second: u8 = self.0[domain.len() + 2];
//         let q_type: u16 = (first as u16) << 8 | second as u16;
//         q_type
//     }
//     fn get_class(&self) -> u16 {
//         let domain = self.get_domain();
//         let first: u8 = self.0[domain.len() + 3];
//         let second: u8 = self.0[domain.len() + 4];
//         let class: u16 = (first as u16) << 8 | second as u16;
//         class
//     }
//     fn get_ttl(&self) -> u32 {
//         let domain = self.get_domain();
//         let first: u8 = self.0[domain.len() + 5];
//         let second: u8 = self.0[domain.len() + 6];
//         let third: u8 = self.0[domain.len() + 7];
//         let fourth: u8 = self.0[domain.len() + 8];
//         println!("hello {:?} {:?} {:?} {:?}", first, second, third, fourth);
//         let ttl: u32 = ((first as u32) << 24)
//             | ((second as u32) << 16)
//             | ((third as u32) << 8)
//             | fourth as u32;
//         ttl
//     }
//     fn get_len(&self) -> u16 {
//         let domain = self.get_domain();
//         let first: u8 = self.0[domain.len() + 9];
//         let second: u8 = self.0[domain.len() + 10];
//         let len: u16 = (first as u16) << 8 | second as u16;
//         len
//     }
//     fn get_rdata(&self) -> Ipv4Addr {
//         let domain = self.get_domain();
//         let first: u8 = self.0[domain.len() + 11];
//         let second: u8 = self.0[domain.len() + 12];
//         let third: u8 = self.0[domain.len() + 13];
//         let fourth: u8 = self.0[domain.len() + 14];
//
//         let rdata = Ipv4Addr::new(first, second, third, fourth);
//         rdata
//     }
// }

// fn main() -> color_eyre::Result<()> {
//     color_eyre::install()?;
//
//     let mut file = File::open("response_packet.bin")?;
//     let bytes = file.bytes().collect::<Vec<_>>();
//     let bytes_vec = sequence(bytes)?;
//     // let mut data = ByteContainer::new();
//
//     // file.read(&mut data.list)?;
//
//     // println!("{:?}", data);
//
//     // println!("total bytes: {:?}", bytes_vec);
//
//     let header_bytes = HeaderBytes::try_from(&bytes_vec)?;
//     // let question_bytes = Question::try_from(&bytes_vec)?;
//     // println!("question bytes {:?}", question_bytes);
//     let record_bytes = RecordBytes::try_from(&bytes_vec)?;
//     println!("record bytes {:?}", record_bytes);
//
//     // println!("domain: {:?}", question_bytes.get_domain());
//     // println!("question type: {:?}", question_bytes.get_type());
//     // println!("class : {:?}", question_bytes.get_class());
//
//     println!("Id: {:?}", header_bytes.get_id());
//     println!("Is Query: {:?}", header_bytes.get_query_response());
//     println!("opcode: {:?}", header_bytes.get_opcode());
//     println!("authoritative ans: {:?}", header_bytes.get_auth_ans());
//     println!("trucated message: {:?}", header_bytes.get_tc_msg());
//     println!(
//         "recursion desired: {:?}",
//         header_bytes.get_recursion_desired()
//     );
//     println!(
//         "recursion available: {:?}",
//         header_bytes.get_recursion_available()
//     );
//     println!("get reserved: {:?}", header_bytes.get_reserved());
//     println!("response code: {:?}", header_bytes.get_response_code());
//     println!("question count: {:?}", header_bytes.get_question_count());
//     println!("answer count: {:?}", header_bytes.get_answer_count());
//     println!("authority count: {:?}", header_bytes.get_authority_count());
//     println!(
//         "additional count: {:?}",
//         header_bytes.get_additional_count()
//     );
//
//     println!("domain: {:?}", record_bytes.get_domain());
//     println!("type: {:?}", record_bytes.get_type());
//     println!("class: {:?}", record_bytes.get_class());
//     println!("ttl: {:?}", record_bytes.get_ttl());
//     println!("len: {:?}", record_bytes.get_len());
//     println!("rdata: {:?}", record_bytes.get_rdata());
//
//     // let mut query_buff = Vec::new();
//     // for i in file.bytes() {
//     //     match i {
//     //         Ok(val) => query_buff.push(val),
//     //         _ => println!("Error"),
//     //     }
//     // }
//     // let mut header = Vec::new();
//     // let mut lbl_sequence = Vec::new();
//     // let mut class_name = Vec::new();
//     // let mut type_name = Vec::new();
//     // let length = query_buff.len();
//     // let mut count = 0;
//     // for i in query_buff.clone().into_iter() {
//     //     if count < 13 {
//     //         header.push(i);
//     //         count += 1;
//     //     } else if length - count <= 2 {
//     //         type_name.push(i);
//     //         count += 1;
//     //     } else if length - count <= 4 {
//     //         class_name.push(i);
//     //         count += 1;
//     //     } else {
//     //         lbl_sequence.push(i);
//     //         count += 1;
//     //     }
//     // }
//     //
//     // println!("This is complete query: {:?}", query_buff);
//     // println!("This is header: {:?}", header);
//     // println!("This is Label: {:?}", lbl_sequence);
//     // println!("This is Type: {:?}", type_name);
//     // println!("This is Class: {:?}", class_name);
//     //
//     Ok(())
//
//     // let s = std::str::from_utf8(&query_res[1..31]).unwrap();
//     // // println!("{}", s);
//     // match s {
//     //     Ok(val) => println!("{}", val),
//     //     Err(e) => println!("{e}"),
//     // }
// }

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ResponseCode {
    ERROR = 1,
    ERROR2 = 2,
    ERROR3 = 3,
    ERROR4 = 4,
    ERROR5 = 5,
    NoError = 0,
}

impl ResponseCode {
    fn get_code(val: u8) -> ResponseCode {
        match val {
            1 => ResponseCode::ERROR,
            2 => ResponseCode::ERROR2,
            3 => ResponseCode::ERROR3,
            4 => ResponseCode::ERROR4,
            5 => ResponseCode::ERROR5,
            _ => ResponseCode::NoError,
        }
    }
}

#[derive(Clone, Debug)]
struct Header {
    id: u16,
    recursion_desired: bool,
    truncated_message: bool,
    authoritative_answer: bool,
    opcode: u8,
    response: bool,
    rescode: ResponseCode,
    checking_disabled: bool,
    authed_data: bool,
    z: bool,
    recursion_available: bool,
    questions: u16,
    answers: u16,
    authoritative_entries: u16,
    resource_entries: u16,
}

impl Header {
    fn create() -> Header {
        Header {
            id: 0,
            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,
            rescode: ResponseCode::NoError,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    fn read(&mut self, buff: &mut ByteContainer) {
        self.id = buff.read_u16().unwrap_or(0);

        let first_flags = buff.read().unwrap_or(0);
        self.recursion_desired = (first_flags & (1 << 0)) > 0;
        self.truncated_message = (first_flags & (1 << 1)) > 0;
        self.authoritative_answer = (first_flags & (1 << 2)) > 0;
        self.opcode = (first_flags >> 3) & 0x0F;
        self.response = (first_flags & (1 << 7)) > 0;

        let second_flags = buff.read().unwrap_or(0);
        self.rescode = ResponseCode::get_code(second_flags & 0x0F);
        self.checking_disabled = (second_flags & (1 << 4)) > 0;
        self.authed_data = (second_flags & (1 << 5)) > 0;
        self.z = (second_flags & (1 << 6)) > 0;
        self.recursion_available = (second_flags & (1 << 7)) > 0;

        self.questions = buff.read_u16().unwrap_or(0);
        self.answers = buff.read_u16().unwrap_or(0);
        self.authoritative_entries = buff.read_u16().unwrap_or(0);
        self.resource_entries = buff.read_u16().unwrap_or(0);
    }
}

#[derive(Clone, Debug)]
enum QueryType {
    A,
    AAAA,
    CNAME,
    UnKnown(u16),
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UnKnown(x) => x,
            QueryType::A => 1,
            QueryType::AAAA => 28,
            QueryType::CNAME => 5,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            5 => QueryType::CNAME,
            28 => QueryType::AAAA,
            _ => QueryType::UnKnown(num),
        }
    }
}

#[derive(Clone, Debug)]
struct Question {
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

#[derive(Clone, Debug)]
enum Record {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
}

impl Record {
    pub fn read(buffer: &mut ByteContainer) -> Result<Record, DnsErrors> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(Record::A { domain, addr, ttl })
            }

            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(Record::AAAA { domain, addr, ttl })
            }

            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(Record::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::UnKnown(_) => {
                buffer.skip(data_len as usize)?;

                Ok(Record::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }
}
#[derive(Clone, Debug)]
struct DnsPacket {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    resources: Vec<Record>,
}
impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: Header::create(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut ByteContainer) -> Result<DnsPacket, DnsErrors> {
        let mut result = DnsPacket::new();
        result.header.read(buffer);

        for _ in 0..result.header.questions {
            let mut question = Question::new("".to_string(), QueryType::UnKnown(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = Record::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = Record::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = Record::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }
}

fn main() -> color_eyre::Result<()> {
    let mut f = File::open("response_packet.bin")?;
    let mut buffer = ByteContainer::new();
    f.read(&mut buffer.list)?;

    let packet = DnsPacket::from_buffer(&mut buffer).unwrap();
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
