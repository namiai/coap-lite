/// The response codes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResponseType {
    // 200 Codes
    Created,
    Deleted,
    Valid,
    Changed,
    Content,
    Continue,

    // 400 Codes
    BadRequest,
    Unauthorized,
    BadOption,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    NotAcceptable,
    PreconditionFailed,
    RequestEntityTooLarge,
    UnsupportedContentFormat,
    RequestEntityIncomplete,
    TooManyRequests,

    // 500 Codes
    InternalServerError,
    NotImplemented,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
    ProxyingNotSupported,

    UnKnown,
}
