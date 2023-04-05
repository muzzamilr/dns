use std::fs::File;
use std::io::Read;

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
struct ByteContainer {
    list: [u8; 512],
    position: usize,
}

impl ByteContainer {
    fn new() -> ByteContainer {
        ByteContainer {
            list: [0; 512],
            position: 0,
        }
    }
    fn position(&self) -> usize {
        self.position
    }
    fn skip(&mut self, steps: usize) -> Result<(), DnsErrors> {
        self.position += steps;
        Ok(())
    }
    fn change_position(&mut self, position: usize) -> Result<(), DnsErrors> {
        self.position = position;
        Ok(())
    }
}

#[derive(Debug)]
enum DnsErrors {
    InsufficientBytesForHeader,
    InsufficientBytesForQuestion,
    ByteContainerError,
}

fn sequence<T, E: std::fmt::Debug + std::fmt::Display>(
    list: Vec<Result<T, E>>,
) -> Result<Vec<T>, E> {
    let mut res = Vec::new();

    for r in list {
        res.push(r?);
        // match r {
        //     Err(e) => return Err(e),
        //     Ok(val) => {
        //         res.push(val);
        //     }
        // }
    }

    Ok(res)
}

// enum Errors {
//     InsufficientBytesForHeader,
//     InsufficientBytesForDomain,
// }

// #[derive(Debug)]
// struct InsufficientBytesForHeader;

impl std::fmt::Display for DnsErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Insufficient bytes for the header")
    }
}
impl std::error::Error for DnsErrors {}

struct HeaderBytes([u8; 12]);

impl TryFrom<&Vec<u8>> for HeaderBytes {
    type Error = DnsErrors;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let bytes = value.iter().take(12).collect::<Vec<_>>();

        if bytes.len() != 12 {
            Err(DnsErrors::InsufficientBytesForHeader)
        } else {
            let mut res = [0; 12];

            bytes.iter().zip(0..12).for_each(|(&&val, idx)| {
                res[idx] = val;
            });

            Ok(HeaderBytes(res))
        }
    }
}

impl HeaderBytes {
    fn get_id(&self) -> u16 {
        let id: u16 = (self.0[0] as u16) << 8 | self.0[1] as u16;
        id
    }
    fn get_query_response(&self) -> bool {
        let tmp_byte = self.0[2];
        let mask = 0x80; // -> binary(10000000)
        let masked_value = tmp_byte & mask;

        masked_value > 0
    }
    fn get_opcode(&self) -> u8 {
        let tmp = self.0[2];
        let rt_sf = tmp >> 3;
        // let lt_sf = rt_sf << 1;
        let mask = 0x0f;
        let opcode = rt_sf & mask;
        opcode
    }
    fn get_auth_ans(&self) -> bool {
        let tmp = self.0[2];
        let mask = 0x4;
        let masked_value = tmp & mask;
        masked_value > 0
    }
    fn get_tc_msg(&self) -> bool {
        let tmp = self.0[2];
        let mask = 0x2;
        let masked_value = tmp & mask;
        masked_value > 0
    }
    fn get_recursion_desired(&self) -> bool {
        let tmp = self.0[2];
        let mask = 0x1;
        let masked_value = tmp & mask;
        masked_value > 0
    }
    fn get_recursion_available(&self) -> bool {
        let tmp = self.0[3];
        let mask = 0x80;
        let masked_value = tmp & mask;
        masked_value > 0
    }
    fn get_reserved(&self) -> u8 {
        let tmp = self.0[3];
        let rt_sf = tmp >> 4;
        // let lt_sf = rt_sf << 4;
        let mask = 0x7;
        let reserved = rt_sf & mask;
        reserved
    }
    fn get_response_code(&self) -> u8 {
        let tmp = self.0[3];
        // let rt_sf = tmp >> 4;
        // let lt_sf = tmp << 4;
        // lt_sf
        let mask = 0x0f;
        let response_code = tmp & mask;
        response_code
    }
    fn get_question_count(&self) -> u16 {
        let qd: u16 = (self.0[4] as u16) << 8 | self.0[5] as u16;
        qd
    }
    fn get_answer_count(&self) -> u16 {
        let an: u16 = (self.0[6] as u16) << 8 | self.0[7] as u16;
        an
    }
    fn get_authority_count(&self) -> u16 {
        let ns: u16 = (self.0[8] as u16) << 8 | self.0[9] as u16;
        ns
    }
    fn get_additional_count(&self) -> u16 {
        let ar: u16 = (self.0[10] as u16) << 8 | self.0[11] as u16;
        ar
    }
}

#[derive(Debug)]
struct Question(Vec<u8>);
// #[derive(Debug)]
// struct InsufficientBytesForQuestion;

// impl std::fmt::Display for InsufficientBytesForQuestion {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "Insufficient bytes for the question")
//     }
// }
// impl std::error::Error for InsufficientBytesForHeader {}
impl TryFrom<&Vec<u8>> for Question {
    type Error = DnsErrors;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let length = value[12];
        let mut domain = Vec::new();
        let count = 13 as usize;
        let mut question = Vec::new();
        if length == 0 {
            Err(DnsErrors::InsufficientBytesForQuestion)
        } else {
            let mut i = 0;
            while value[count + i] != 0 {
                domain.push(value[count + i]);
                question.push(value[count + i]);
                i += 1;
            }
            for x in count + domain.len()..count + domain.len() + 5 {
                question.push(value[x]);
            }

            Ok(Question(question))
        }
    }
}

impl Question {
    fn get_domain(&self) -> Vec<u8> {
        let mut domain = Vec::new();
        let mut n = 0;
        while self.0[n] != 0 {
            domain.push(self.0[n]);
            n += 1;
        }
        domain
    }
    fn get_type(&self) -> u16 {
        let domain = self.get_domain();
        let first: u8 = self.0[domain.len() + 1];
        let second: u8 = self.0[domain.len() + 2];
        let q_type: u16 = (first as u16) << 8 | second as u16;
        q_type
    }
    fn get_class(&self) -> u16 {
        let domain = self.get_domain();
        let first: u8 = self.0[domain.len() + 3];
        let second: u8 = self.0[domain.len() + 4];
        let class: u16 = (first as u16) << 8 | second as u16;
        class
    }
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let file = File::open("response_packet.bin")?;
    let bytes = file.bytes().collect::<Vec<_>>();
    let bytes_vec = sequence(bytes)?;

    let header_bytes = HeaderBytes::try_from(&bytes_vec)?;

    let question_bytes = Question::try_from(&bytes_vec)?;
    println!("domain: {:?}", question_bytes.get_domain());

    println!("class : {:?}", question_bytes.get_class());
    println!("question type: {:?}", question_bytes.get_type());
    println!("question type: {:?}", question_bytes.get_type());
    println!("total bytes: {:?}", bytes_vec);
    println!("Id: {:?}", header_bytes.get_id());
    println!("Is Query: {:?}", header_bytes.get_query_response());
    println!("opcode: {:?}", header_bytes.get_opcode());
    println!("authoritative ans: {:?}", header_bytes.get_auth_ans());
    println!("trucated message: {:?}", header_bytes.get_tc_msg());
    println!(
        "recursion desired: {:?}",
        header_bytes.get_recursion_desired()
    );
    println!(
        "recursion available: {:?}",
        header_bytes.get_recursion_available()
    );
    println!("get reserved: {:?}", header_bytes.get_reserved());
    println!("response code: {:?}", header_bytes.get_response_code());
    println!("question count: {:?}", header_bytes.get_question_count());
    println!("answer count: {:?}", header_bytes.get_answer_count());
    println!("authority count: {:?}", header_bytes.get_authority_count());
    println!(
        "additional count: {:?}",
        header_bytes.get_additional_count()
    );
    // let mut query_buff = Vec::new();
    // for i in file.bytes() {
    //     match i {
    //         Ok(val) => query_buff.push(val),
    //         _ => println!("Error"),
    //     }
    // }
    // let mut header = Vec::new();
    // let mut lbl_sequence = Vec::new();
    // let mut class_name = Vec::new();
    // let mut type_name = Vec::new();
    // let length = query_buff.len();
    // let mut count = 0;
    // for i in query_buff.clone().into_iter() {
    //     if count < 13 {
    //         header.push(i);
    //         count += 1;
    //     } else if length - count <= 2 {
    //         type_name.push(i);
    //         count += 1;
    //     } else if length - count <= 4 {
    //         class_name.push(i);
    //         count += 1;
    //     } else {
    //         lbl_sequence.push(i);
    //         count += 1;
    //     }
    // }
    //
    // println!("This is complete query: {:?}", query_buff);
    // println!("This is header: {:?}", header);
    // println!("This is Label: {:?}", lbl_sequence);
    // println!("This is Type: {:?}", type_name);
    // println!("This is Class: {:?}", class_name);
    //
    Ok(())

    // let s = std::str::from_utf8(&query_res[1..31]).unwrap();
    // // println!("{}", s);
    // match s {
    //     Ok(val) => println!("{}", val),
    //     Err(e) => println!("{e}"),
    // }
}

// struct Query {
//     header: Header,
//     question: Vec<i32>,
//     answer: Vec<i32>,
//     authority: Vec<i32>,
// }

// impl Query {
//     fn new(queryPacket: Vec<u8>) -> Self {
//         let query = Query {
//             header: Header::new(),
//             question: Vec::new(),
//             answer: Vec::new(),
//             authority: Vec::new(),
//         };
//         query
//     }
// }

// struct Header {
//     id: u16,
//     is_query: bool,
//     opcode: Opcode,
//     authoritative_ans: bool,
//     truncation: bool,
//     recursion_desired: bool,
//     recursion_available: bool,
//     resp_code: ResponseCode,
//     question_count: u16,
//     ans_count: u16,
//     name_server_count: u16,
//     additional_records_count: u16,
// }

// impl Header {
//     fn new(header: vec<u8>) {
//         Header{
//             id: vec<>
//         }
//     }
// }
