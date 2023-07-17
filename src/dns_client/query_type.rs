#[derive(Clone, Debug)]
pub enum QueryType {
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
