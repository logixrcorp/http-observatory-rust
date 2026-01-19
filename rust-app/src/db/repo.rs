use sqlx::PgPool;
use crate::db::models::{Site, Scan};
// use crate::scanner::grade::{Grade, TestResult}; // implicitly used via models

#[derive(Clone)]
pub struct Repository {
    pool: PgPool,
}

impl Repository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map(|_| ())
    }

    pub async fn get_site_by_domain(&self, domain: &str) -> Result<Option<Site>, sqlx::Error> {
        sqlx::query_as::<_, Site>(
            "SELECT id, domain, creation_time, public_headers, private_headers, cookies FROM sites WHERE domain = $1"
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn create_site(&self, domain: &str) -> Result<Site, sqlx::Error> {
        sqlx::query_as::<_, Site>(
            "INSERT INTO sites (domain, creation_time) VALUES ($1, NOW()) RETURNING id, domain, creation_time, public_headers, private_headers, cookies"
        )
        .bind(domain)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_latest_scan(&self, site_id: i32) -> Result<Option<Scan>, sqlx::Error> {
        sqlx::query_as::<_, Scan>(
            "SELECT * FROM scans WHERE site_id = $1 ORDER BY start_time DESC LIMIT 1"
        )
        .bind(site_id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn save_scan(&self, site_id: i32, results: &[crate::scanner::grade::TestResult], score: i16, grade: crate::scanner::grade::Grade, error: Option<String>) -> Result<i32, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        
        // State
        let state = if error.is_some() { crate::db::models::ScanState::Aborted } else { crate::db::models::ScanState::Finished };

        // Insert Scan
        let scan_id: i32 = sqlx::query_scalar(
            "INSERT INTO scans (site_id, state, start_time, tests_quantity, grade, score, algorithm_version, error) 
             VALUES ($1, $2, NOW(), $3, $4, $5, 2, $6) RETURNING id"
        )
        .bind(site_id)
        .bind(state)
        .bind(results.len() as i16)
        .bind(grade)
        .bind(score)
        .bind(error)
        .fetch_one(&mut *tx)
        .await?;

        // Insert Tests
        for r in results {
            sqlx::query(
                "INSERT INTO tests (site_id, scan_id, name, expectation, result, score_modifier, pass, output)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, '{}')"
            )
            .bind(site_id)
            .bind(scan_id)
            .bind(r.to_string())
            .bind(r.to_string()) // Using result name as expectation for now
            .bind(r)
            .bind(r.modifier())
            .bind(r.modifier() >= 0)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        
        Ok(scan_id)
    }
    pub async fn get_test_results(&self, scan_id: i32) -> Result<Vec<crate::db::models::Test>, sqlx::Error> {
        sqlx::query_as::<_, crate::db::models::Test>(
            "SELECT * FROM tests WHERE scan_id = $1 ORDER BY id ASC"
        )
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_host_history(&self, site_id: i32) -> Result<Vec<crate::db::models::HostHistoryEntry>, sqlx::Error> {
        // Rust equiv of: select id as scan_id, start_time, score, grade from scans where site_id = $1 and state='FINISHED' order by start_time DESC
        sqlx::query_as::<_, crate::db::models::HostHistoryEntry>(
            "SELECT id as scan_id, start_time, score, grade FROM scans WHERE site_id = $1 AND state = 'FINISHED' ORDER BY start_time DESC"
        )
        .bind(site_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_recent_scans(&self, limit: i64) -> Result<Vec<crate::db::models::RecentScanEntry>, sqlx::Error> {
        sqlx::query_as::<_, crate::db::models::RecentScanEntry>(
             "SELECT sites.domain, scans.score, scans.grade, scans.start_time 
              FROM scans 
              JOIN sites ON scans.site_id = sites.id 
              WHERE scans.state = 'FINISHED' 
              ORDER BY scans.start_time DESC 
              LIMIT $1"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }
    pub async fn get_grade_distribution(&self) -> Result<Vec<crate::db::models::GradeDistributionEntry>, sqlx::Error> {
        // Rust equiv of: select grade, count(*) from scans where state='FINISHED' group by grade
        // Or using the materialized view: select grade, count from grade_distribution_all_scans
        // Since we don't have the MV fully operational/managed in Rust yet, we'll use the raw query.
        sqlx::query_as::<_, crate::db::models::GradeDistributionEntry>(
            "SELECT grade, count(*) as count FROM scans WHERE state = 'FINISHED' GROUP BY grade ORDER BY grade ASC"
        )
        .fetch_all(&self.pool)
        .await
    }
}
