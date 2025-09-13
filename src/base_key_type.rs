#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum BaseKeyType {
    Ours = 1,
    Theirs = 2,
}

impl TryFrom<u8> for BaseKeyType {
    type Error = String;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(BaseKeyType::Ours),
            2 => Ok(BaseKeyType::Theirs),
            _ => Err(format!("Invalid BaseKeyType value: {}", value)),
        }
    }
}


impl From<BaseKeyType> for u8 {
    fn from(value: BaseKeyType) -> Self {
        value as u8
    }
}