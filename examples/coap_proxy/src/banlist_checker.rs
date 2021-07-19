use crate::redis::Commands;
use std::collections::HashSet;

pub trait BanListChecker: Send + Sync {
    fn cn_is_banned(&self, cn: &str) -> Result<bool, BanListCheckerError>;
}

#[derive(Debug)]
pub enum BanListCheckerError {
    InitError(String),
    CheckError(String),
}

impl std::fmt::Display for BanListCheckerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
        Self::InitError(e) => write!(f, "Failed to initialize the checker due to the following error: {}", e),
        Self::CheckError(e) => write!(f, "Failed to check through the banlist due to the following error: {}", e),
    }
    }
}

pub struct StaticBanListChecker {
    banned_cns: HashSet<String>,
}

impl StaticBanListChecker {
    #[allow(dead_code)]
    pub fn new(cns: Vec<&str>) -> StaticBanListChecker {
        let mut hs = HashSet::with_capacity(cns.len());
        for cn in cns {
            hs.insert(cn.to_owned());
        }
        StaticBanListChecker { banned_cns: hs }
    }
}

impl BanListChecker for StaticBanListChecker {
    fn cn_is_banned(&self, cn: &str) -> Result<bool, BanListCheckerError> {
        Ok(self.banned_cns.contains(cn))
    }
}

/**
 * Simple ban list checker that checks if the provided common name exists in redis database
*/
pub struct RedisBanListChecker {
    redis_pool: r2d2::Pool<redis::Client>,
}

impl RedisBanListChecker {
    pub fn new(
        connection_url: &str,
    ) -> Result<RedisBanListChecker, BanListCheckerError> {
        let client = redis::Client::open(connection_url)
            .map_err(|e| BanListCheckerError::InitError(e.to_string()))?;
        let pool = r2d2::Pool::builder()
            .build(client)
            .map_err(|e| BanListCheckerError::InitError(e.to_string()))?;
        Ok(RedisBanListChecker { redis_pool: pool })
    }
}

impl BanListChecker for RedisBanListChecker {
    fn cn_is_banned(&self, cn: &str) -> Result<bool, BanListCheckerError> {
        let mut connection = self
            .redis_pool
            .get()
            .map_err(|e| BanListCheckerError::CheckError(e.to_string()))?;
        let key_value: Option<String> = connection
            .get::<&str, Option<String>>(cn)
            .map_err(|e| BanListCheckerError::CheckError(e.to_string()))?
            .into();
        if let Some(_) = key_value {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
