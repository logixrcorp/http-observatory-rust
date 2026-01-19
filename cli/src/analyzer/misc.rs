use crate::grader::TestResult;
use reqwest::StatusCode;

pub fn analyze_security_txt(status: StatusCode) -> TestResult {
    if status == StatusCode::OK {
        TestResult::SecurityTxtImplemented
    } else {
        TestResult::SecurityTxtNotImplemented
    }
}
