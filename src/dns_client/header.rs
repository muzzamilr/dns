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

impl ResponseCode {
    pub fn get_code(val: u8) -> ResponseCode {
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

impl Header {
    pub fn create() -> Header {
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

    pub fn read(&mut self, buff: &mut ByteContainer) {
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
