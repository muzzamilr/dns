use crate::errors::DnsErrors;

#[derive(Clone, Debug)]
pub enum QueryType {
    A,
    AAAA,
    CNAME,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::A => 1,
            QueryType::AAAA => 28,
            QueryType::CNAME => 5,
        }
    }

    pub fn from_num(num: u16) -> Result<QueryType, DnsErrors> {
        match num as usize {
            1 => Ok(QueryType::A),
            5 => Ok(QueryType::CNAME),
            28 => Ok(QueryType::AAAA),
            _ => Err(DnsErrors::QueryTypeMismatch),
        }
    }
}
