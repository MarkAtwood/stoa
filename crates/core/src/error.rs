use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum CoreError {
    InvalidGroupName(String),
    InvalidMessageId(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::InvalidGroupName(name) => {
                write!(f, "invalid group name: {:?}", name)
            }
            CoreError::InvalidMessageId(id) => {
                write!(f, "invalid message-id: {:?}", id)
            }
        }
    }
}

impl std::error::Error for CoreError {}
