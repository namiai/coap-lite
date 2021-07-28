use std::fmt;
use std::io;

#[derive(Debug)]
pub enum CoapProxyError {
    ChannelWriteError,
    AddrNotAvailable,
    InvalidCommandLineParameter(String),
    BindError,
    AcceptingConnectionError(io::Error),
    StreamReadError,
    StreamWriteError,
}

impl fmt::Display for CoapProxyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &CoapProxyError::ChannelWriteError => {
                write!(f, "Failed to write to the channel")
            }
            &CoapProxyError::AddrNotAvailable => {
                write!(f, "Address is not available")
            }
            CoapProxyError::InvalidCommandLineParameter(e) => {
                write!(f, "Invalid command line parameter {}", e)
            }
            &CoapProxyError::BindError => write!(f, "Cannot bind the port"),
            CoapProxyError::AcceptingConnectionError(e) => {
                write!(
                    f,
                    "Cannot accept incoming connection: {}",
                    e.to_string()
                )
            }
            &CoapProxyError::StreamReadError => {
                write!(f, "Cannot read from the stream")
            }
            &CoapProxyError::StreamWriteError => {
                write!(f, "Cannot write to the stream")
            }
        }
    }
}

impl std::error::Error for CoapProxyError {}
