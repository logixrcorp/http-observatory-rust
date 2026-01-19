use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("DNS resolution failed: {0}")]
    Dns(String),
    #[error("Connection refused: {0}")]
    ConnectionRefused(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("Request failed: {0}")]
    Request(String),
    #[error("Redirection chain failed: {0}")]
    Chain(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Other: {0}")]
    Other(String),
}

impl From<reqwest::Error> for ScannerError {
    fn from(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            ScannerError::Timeout(error.to_string())
        } else if error.is_connect() {
             ScannerError::ConnectionRefused(error.to_string())
        } else if error.is_builder() {
             ScannerError::Request(format!("Builder error: {}", error))
        } else if error.is_request() {
             ScannerError::Request(format!("Request error: {}", error))
        } else if error.is_redirect() {
             ScannerError::Chain(format!("Redirect error: {}", error))
        } else {
             ScannerError::Other(error.to_string())
        }
    }
}

impl From<url::ParseError> for ScannerError {
    fn from(error: url::ParseError) -> Self {
        ScannerError::Request(format!("URL parse error: {}", error))
    }
}

