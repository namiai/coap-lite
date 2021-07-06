#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignalType {
    CSM,
    Ping,
    Pong,
    Release,
    Abort,
}
