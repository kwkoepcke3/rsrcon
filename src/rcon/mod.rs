use std::net::Ipv4Addr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const MIN_PACKET_SIZE: usize = 10;
const STANDARD_ID: i32 = 1337;
const EXT_RESP_ID: i32 = 42;
const SIZE_ID: usize = 4;
const SIZE_VARIANT: usize = 4;
const SIZE_TERMINATOR: usize = 1;

pub struct Rcon {
    stream: TcpStream,
}

impl Rcon {
    pub async fn from(ip: Ipv4Addr, port: &str) -> Result<Rcon, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(format!("{ip}:{port}")).await?;

        return Ok(Rcon { stream });
    }

    pub async fn authenticate(
        &mut self,
        password: &str,
    ) -> Result<BasicPacket, Box<dyn std::error::Error>> {
        authenticate(&mut self.stream, password).await
    }

    pub async fn exec_cmd(
        &mut self,
        cmd: &str,
    ) -> Result<Vec<BasicPacket>, Box<dyn std::error::Error>> {
        let mut packets = vec![];
        packets.push(exec_cmd(&mut self.stream, cmd).await?);

        let empty = BasicPacket {
            id: EXT_RESP_ID,
            variant: 2,
            body: vec![],
        };

        self.stream.write_all(&Vec::<u8>::from(empty)[..]).await?;
        self.stream.flush().await?;

        loop {
            let packet = read_packet(&mut self.stream).await?;
            if packet.id == EXT_RESP_ID {
                break;
            }
            packets.push(packet);
        }

        return Ok(packets);
    }
}

#[derive(Clone)]
pub struct BasicPacket {
    pub id: i32,
    pub variant: i32,
    pub body: Vec<u8>,
}

impl BasicPacket {
    pub fn size(&self) -> i32 {
        return (self.body.len() + MIN_PACKET_SIZE) as i32;
    }
}

impl From<BasicPacket> for Vec<u8> {
    fn from(packet: BasicPacket) -> Self {
        return basic_packet_to_bytes(packet);
    }
}

impl From<&[u8]> for BasicPacket {
    fn from(bytes: &[u8]) -> Self {
        return bytes_to_basic_packet(bytes);
    }
}

fn bytes_to_basic_packet(bytes: &[u8]) -> BasicPacket {
    let b_size = &bytes[..4];
    let b_id = &bytes[4..8];
    let b_variant = &bytes[8..12];

    let size = i32::from_le_bytes(b_size.try_into().expect("could not convert b_size to i32"));
    let id = i32::from_le_bytes(b_id.try_into().expect("could not convert b_id to i32"));
    let variant = i32::from_le_bytes(
        b_variant
            .try_into()
            .expect("could not convert b_variant to i32"),
    );

    // size field does not consider itself
    // there are 9 bytes in the packet excluding size that are not body
    // the bytes in body is size - 9
    let i_body_end = 12 + (size as usize) - SIZE_ID - SIZE_VARIANT - SIZE_TERMINATOR;
    let b_body = &bytes[12..i_body_end];

    assert!(
        bytes[i_body_end] == b'\0',
        "RECIEVED PACKET DOES NOT END WITH 0"
    );

    return BasicPacket {
        id,
        variant,
        body: (&b_body[..b_body.len() - 1]).to_vec().into(),
    };
}

fn basic_packet_to_bytes(packet: BasicPacket) -> Vec<u8> {
    let mut buf = vec![0; (packet.size() + 4) as usize];

    buf[..4].copy_from_slice(&packet.size().to_le_bytes()[..]);
    buf[4..8].copy_from_slice(&packet.id.to_le_bytes()[..]);
    buf[8..12].copy_from_slice(&packet.variant.to_le_bytes()[..]);

    let i_body_end = 12 + packet.body.len();
    buf[12..i_body_end].copy_from_slice(&packet.body);
    buf[i_body_end..i_body_end + 2].copy_from_slice(b"\0\0"); // string ends with null terminator, packet also does

    return (&buf[..i_body_end + 2]).to_vec();
}

async fn authenticate(
    stream: &mut TcpStream,
    password: &str,
) -> Result<BasicPacket, Box<dyn std::error::Error>> {
    let auth_packet = BasicPacket {
        id: STANDARD_ID,
        variant: 3,
        body: password.into(),
    };

    stream.write_all(&Vec::<u8>::from(auth_packet)[..]).await?;
    stream.flush().await?;

    read_packet(stream).await
}

async fn exec_cmd(
    stream: &mut TcpStream,
    cmd: &str,
) -> Result<BasicPacket, Box<dyn std::error::Error>> {
    let exec_packet = BasicPacket {
        id: STANDARD_ID,
        variant: 2,
        body: cmd.into(),
    };

    stream.write_all(&Vec::<u8>::from(exec_packet)[..]).await?;
    stream.flush().await?;

    read_packet(stream).await
}

async fn read_packet(stream: &mut TcpStream) -> Result<BasicPacket, Box<dyn std::error::Error>> {
    let mut response_buf_size = [0u8; 4];
    stream.read_exact(&mut response_buf_size).await?;

    let size = i32::from_le_bytes(response_buf_size);
    let mut response_buf = vec![0u8; size as usize];
    stream.read_exact(&mut response_buf).await?;

    let packet: BasicPacket = (&([&response_buf_size[..], &response_buf[..]].concat())[..]).into();

    return Ok(packet);
}
