use dns::{byte_container::ByteContainer, packet::Packet};
use std::fs::File;
use std::io::Read;

// const DNS_IP: &str = "1.1.1.1";
// const PORT: u16 = 53;
// const RES_BUFF: usize = 1024;
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

fn main() -> color_eyre::Result<()> {
    let mut f = File::open("response_packet.bin")?;
    let mut buffer = ByteContainer::new();
    f.read(&mut buffer.list)?;

    let packet = Packet::from_buffer(&mut buffer).unwrap();
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    // for rec in packet.authorities {
    //     println!("{:#?}", rec);
    // }
    // for rec in packet.resources {
    //     println!("{:#?}", rec);
    // }

    Ok(())
}
