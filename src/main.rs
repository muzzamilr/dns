use dns::query_type::QueryType;
use dns::{byte_container::ByteContainer, packet::Packet, question::Question};
// use std::fs::File;
// use std::io::Read;
use clap::Parser;
use tokio::net::UdpSocket;

// const DNS_IP: &str = "1.1.1.1";
// const PORT: u16 = 53;
// const RES_BUFF: usize = 512;
// const DNS_SERVER: (&str, u16) = (DNS_IP, PORT);

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

#[derive(Parser, Debug)]
struct Arguments {
    query_name: String,
    query_type: String,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    // let mut f = File::open("response_packet.bin")?;
    // let mut buffer = ByteContainer::new();
    // f.read(&mut buffer.list)?;

    let args = Arguments::parse();

    let a = match args.query_type.to_uppercase().as_str() {
        "A" => Ok(QueryType::A),
        "AAAA" => Ok(QueryType::AAAA),
        "CNAME" => Ok(QueryType::CNAME),
        _ => Err("Invalid query type".to_string()),
    };

    let qname = args.query_name;
    let qtype = a.unwrap();
    let server = ("1.1.1.1", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 8085)).await?;

    let mut packet = Packet::default();

    packet.header.id = 1234;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(Question::try_from(qname.to_string(), qtype)?);

    let mut req_buffer = ByteContainer::default();
    packet.to_buffer(&mut req_buffer)?;
    socket
        .send_to(&req_buffer.list[0..req_buffer.pos], server)
        .await?;

    let mut res_buffer = ByteContainer::default();
    socket.recv_from(&mut res_buffer.list).await?;

    let res_packet = Packet::from_buffer(&mut res_buffer)?;
    // println!("{:?}", res_packet.header);

    for _q in res_packet.questions {
        // println!("{:?}", q);
    }
    for rec in res_packet.record {
        println!("{:?}", rec);
    }

    Ok(())
}
