/// The request codes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RequestType {
    Get,
    Post,
    Put,
    Delete,
    UnKnown,
    CSM,
}
