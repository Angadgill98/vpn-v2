use std::fmt;




#[derive(Debug)]
pub enum ServerError{
    TunError(tun::Error),
    RTError(rtnetlink::Error),
    InterfaceError(String),
    IO_Error(std::io::Error)
}



impl From<tun::Error> for ServerError {
    fn from(value: tun::Error) -> Self {
        ServerError::TunError(value)
    }
}

impl From<rtnetlink::Error> for ServerError {
    fn from(value: rtnetlink::Error) -> Self {
        ServerError::RTError(value)
    }
}

impl From<std::io::Error> for ServerError {
    fn from(value: std::io::Error) -> Self {
        ServerError::IO_Error(value)
    }
}



impl std::error::Error for ServerError {}


impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::TunError(e) => {
                write!(f, "TUN error: {}", e)
            }
            ServerError::RTError((e))=> {
                write!(f, "RT error: {}", e)
            }
            ServerError::InterfaceError(e)=> {
                write!(f, "Interface error: {}", e)
            }
            ServerError::IO_Error(e)=> {
                write!(f, "IO error: {}", e)
            }
        }
    }
}
