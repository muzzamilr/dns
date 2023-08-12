use crate::errors::DnsErrors;

use super::byte_container::ByteContainer;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseCode {
    ERROR = 1,
    ERROR2 = 2,
    ERROR3 = 3,
    ERROR4 = 4,
    ERROR5 = 5,
    NoError = 0,
}

impl TryFrom<u8> for ResponseCode {
    type Error = DnsErrors;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(ResponseCode::ERROR),
            2 => Ok(ResponseCode::ERROR2),
            3 => Ok(ResponseCode::ERROR3),
            4 => Ok(ResponseCode::ERROR4),
            5 => Ok(ResponseCode::ERROR5),
            0 => Ok(ResponseCode::NoError),
            _ => Err(DnsErrors::ResponseCodeError),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Header {
    pub id: u16,
    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub response: bool,
    pub rescode: ResponseCode,
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool,
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl Default for Header {
    fn default() -> Self {
        Self::new()
    }
}

impl Header {
    pub fn new() -> Header {
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
    pub fn from_buffer(buff: &mut ByteContainer) -> Result<Self, DnsErrors> {
        let id = buff.read_u16()?;

        let first_flags = buff.read()?;
        let recursion_desired = (first_flags & (1 << 0)) > 0;
        let truncated_message = (first_flags & (1 << 1)) > 0;
        let authoritative_answer = (first_flags & (1 << 2)) > 0;
        let opcode = (first_flags >> 3) & 0x0F;
        let response = (first_flags & (1 << 7)) > 0;

        let second_flags = buff.read()?;
        let rescode = ResponseCode::try_from(second_flags & 0x0F)?;
        let checking_disabled = (second_flags & (1 << 4)) > 0;
        let authed_data = (second_flags & (1 << 5)) > 0;
        let z = (second_flags & (1 << 6)) > 0;
        let recursion_available = (second_flags & (1 << 7)) > 0;

        let questions = buff.read_u16()?;
        let answers = buff.read_u16()?;
        let authoritative_entries = buff.read_u16()?;
        let resource_entries = buff.read_u16()?;

        Ok(Header {
            id,
            recursion_desired,
            truncated_message,
            authoritative_answer,
            opcode,
            response,
            rescode,
            checking_disabled,
            authed_data,
            z,
            recursion_available,
            questions,
            answers,
            authoritative_entries,
            resource_entries,
        })
    }
    pub fn write(&self, buffer: &mut ByteContainer) -> Result<(), DnsErrors> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}
