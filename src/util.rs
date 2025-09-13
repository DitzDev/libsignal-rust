use base64::{Engine as _, engine::general_purpose};

pub struct Util;

impl Util {
    /// Converts the input data to a string.
    /// If the input is a byte slice, it converts it to a base64-encoded string.
    pub fn to_string(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }

    /// Compares two inputs for equality after converting them to strings.
    /// Performs a safe substring comparison with a minimum length of 5 characters.
    pub fn is_equal(a: Option<&[u8]>, b: Option<&[u8]>) -> Result<bool, Box<dyn std::error::Error>> {
        if a.is_none() || b.is_none() {
            return Ok(false);
        }

        let a_str = Self::to_string(a.unwrap());
        let b_str = Self::to_string(b.unwrap());

        let max_length = std::cmp::max(a_str.len(), b_str.len());
        if max_length < 5 {
            return Err("Cannot compare inputs: length of inputs is too short (less than 5 characters).".into());
        }

        // Perform substring comparison
        Ok(a_str[..max_length] == b_str[..max_length])
    }
}