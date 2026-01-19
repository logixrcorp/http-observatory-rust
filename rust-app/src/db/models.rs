use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use serde_json::Value;
use chrono::NaiveDateTime;
use crate::scanner::grade::{Grade, TestResult};

use std::str::FromStr;
use std::error::Error;
use sqlx::{Postgres, Type, Decode, Encode};
use sqlx::postgres::{PgTypeInfo, PgValueRef, PgArgumentBuffer};
use strum::{Display, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, EnumString)]
pub enum ScanState {
    #[strum(serialize = "STARTING")]
    Starting,
    #[strum(serialize = "FINISHED")]
    Finished,
    #[strum(serialize = "ABORTED")]
    Aborted,
    #[strum(serialize = "FAILED")]
    Failed,
}

impl Type<Postgres> for ScanState {
    fn type_info() -> PgTypeInfo {
        <String as Type<Postgres>>::type_info()
    }
}

impl<'r> Decode<'r, Postgres> for ScanState {
    fn decode(value: PgValueRef<'r>) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
        let s = <String as Decode<Postgres>>::decode(value)?;
        ScanState::from_str(&s).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync + 'static>)
    }
}

impl<'q> Encode<'q, Postgres> for ScanState {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        <String as Encode<Postgres>>::encode_by_ref(&self.to_string(), buf)
    }
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Site {
    pub id: i32,
    pub domain: String,
    pub creation_time: NaiveDateTime,
    pub public_headers: Option<Value>,
    pub private_headers: Option<Value>,
    pub cookies: Option<Value>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Scan {
    pub id: i32,
    pub site_id: i32,
    pub state: ScanState,
    pub start_time: NaiveDateTime,
    pub end_time: Option<NaiveDateTime>,
    pub algorithm_version: i16,
    pub tests_failed: i16,
    pub tests_passed: i16,
    pub tests_quantity: i16,
    pub grade: Option<Grade>,
    pub score: Option<i16>,
    pub likelihood_indicator: Option<String>,
    pub error: Option<String>,
    pub response_headers: Option<Value>,
    pub hidden: bool,
    pub status_code: Option<i16>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Test {
    pub id: i64,
    pub site_id: i32,
    pub scan_id: i32,
    pub name: String,
    pub expectation: String,
    pub result: TestResult,
    pub score_modifier: i16,
    pub pass: bool,
    pub output: Value,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct HostHistoryEntry {
    pub scan_id: i32,
    pub start_time: NaiveDateTime,
    pub score: Option<i16>,
    pub grade: Option<Grade>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct RecentScanEntry {
    pub domain: String,
    pub score: Option<i16>,
    pub grade: Option<Grade>,
    pub start_time: NaiveDateTime,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct GradeDistributionEntry {
    pub grade: String,
    pub count: i64,
}
