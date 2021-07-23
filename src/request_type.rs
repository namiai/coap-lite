/// The request codes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RequestType {
    Get,
    Post,
    Put,
    Delete,
    UnKnown,
}

impl From<&str> for RequestType {
    fn from(item: &str) -> Self {
        match item {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "UNKNOWN" => Self::UnKnown,
            _ => Self::UnKnown,
        }
    }
}

impl From<&RequestType> for String {
    fn from(item: &RequestType) -> Self {
        match item {
            RequestType::Get => "GET".to_owned(),
            RequestType::Post => "POST".to_owned(),
            RequestType::Put => "PUT".to_owned(),
            RequestType::Delete => "DELETE".to_owned(),
            RequestType::UnKnown => "UNKNOWN".to_owned(),
        }
    }
}
