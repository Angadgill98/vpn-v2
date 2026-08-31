use std::fmt;




#[derive(Debug)]
pub enum ControllerError{
    TunError(tun::Error),
    RTError(rtnetlink::Error),
    InterfaceError(String),
    IO_Error(std::io::Error)
}



impl From<tun::Error> for ControllerError {
    fn from(value: tun::Error) -> Self {
        ControllerError::TunError(value)
    }
}

impl From<rtnetlink::Error> for ControllerError {
    fn from(value: rtnetlink::Error) -> Self {
        ControllerError::RTError(value)
    }
}

impl From<std::io::Error> for ControllerError {
    fn from(value: std::io::Error) -> Self {
        ControllerError::IO_Error(value)
    }
}



impl std::error::Error for ControllerError {}


impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControllerError::TunError(e) => {
                write!(f, "TUN error: {}", e)
            }
            ControllerError::RTError((e))=> {
                write!(f, "RT error: {}", e)
            }
            ControllerError::InterfaceError(e)=> {
                write!(f, "Interface error: {}", e)
            }
            ControllerError::IO_Error(e)=> {
                write!(f, "IO error: {}", e)
            }
        }
    }
}
