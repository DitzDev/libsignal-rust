#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum ChainType {
    Sending = 1,
    Receiving = 2,
}

impl TryFrom<u8> for ChainType {
    type Error = String;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ChainType::Sending),
            2 => Ok(ChainType::Receiving),
            _ => Err(format!("Invalid ChainType value: {}", value)),
        }
    }
}


impl From<ChainType> for u8 {
    fn from(value: ChainType) -> Self {
        value as u8
    }
}