use std::fs::File;
use std::io::Read;

// const DNS_IP: &str = "8.8.8.8"; // Public DNS Server
// const PORT: u16 = 53;
// const RES_BUFF: usize = 1024; // Size for the response buffer
// const DNS_SERVER: (&str, u16) = (DNS_IP, PORT);

fn main() {
    let mut query_res = Vec::new();
    let file = File::open("query_packet.bin").expect("not found");
    for i in file.bytes() {
        match i {
            Ok(val) => query_res.push(val),
            _ => println!("Error"),
        }
    }

    // let s = std::str::from_utf8(&query_res[1..31]).unwrap();
    // // println!("{}", s);
    // match s {
    //     Ok(val) => println!("{}", val),
    //     Err(e) => println!("{e}"),
    // }

    println!("{:?}", query_res);
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
