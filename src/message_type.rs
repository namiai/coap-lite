/// The message types.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
    Confirmable,
    NonConfirmable,
    Acknowledgement,
    Reset,
}
