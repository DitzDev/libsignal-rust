#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolAddress {
    pub id: String,
    pub device_id: u32,
}

impl ProtocolAddress {
    pub fn from_string(encoded_address: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_encoded(encoded_address)
    }

    pub fn from_encoded(encoded_address: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if encoded_address.matches('.').count() != 1 {
            return Err("Invalid address encoding: must contain exactly one '.' character".into());
        }
        
        let parts: Vec<&str> = encoded_address.split('.').collect();
        if parts.len() != 2 {
            return Err("Invalid address encoding: must have exactly two parts separated by '.'".into());
        }
        
        if parts[0].is_empty() {
            return Err("Invalid address encoding: ID part cannot be empty".into());
        }
        
        let device_id = parts[1].parse::<u32>()
            .map_err(|_| "Invalid device ID: must be a valid 32-bit unsigned integer")?;
        
        Self::new(parts[0].to_string(), device_id)
    }

    pub fn new(id: String, device_id: u32) -> Result<Self, Box<dyn std::error::Error>> {
        if id.contains('.') {
            return Err("ProtocolAddress ID cannot contain '.' character - use from_encoded() for encoded addresses".into());
        }
        Ok(Self { id, device_id })
    }

    pub fn to_string(&self) -> String {
        format!("{}.{}", self.id, self.device_id)
    }

    pub fn is(&self, other: &Self) -> bool {
        self.id == other.id && self.device_id == other.device_id
    }
}