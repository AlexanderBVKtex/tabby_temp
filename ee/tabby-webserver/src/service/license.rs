use anyhow::{anyhow, Context};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonwebtoken as jwt;
use lazy_static::lazy_static;
use serde::Deserialize;
use tabby_db::DbConn;
use tabby_schema::{
    is_demo_mode,
    license::{LicenseInfo, LicenseService, LicenseStatus, LicenseType},
    Result,
};

use crate::bail;

lazy_static! {
    static ref LICENSE_DECODING_KEY: jwt::DecodingKey =
        jwt::DecodingKey::from_rsa_pem(include_bytes!("../../keys/license.key.pub")).unwrap();
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
struct LicenseJWTPayload {
    /// Expiration time (as UTC timestamp)
    pub exp: i64,

    /// Issued at (as UTC timestamp)
    pub iat: i64,

    /// Issuer
    pub iss: String,

    /// License grantee email address
    pub sub: String,

    /// License Type
    pub typ: LicenseType,

    /// Number of license (# of seats).
    pub num: usize,
}

fn validate_license(token: &str) -> Result<LicenseJWTPayload, jwt::errors::ErrorKind> {
    let mut validation = jwt::Validation::new(jwt::Algorithm::RS512);
    validation.validate_exp = false;
    validation.set_issuer(&["tabbyml.com"]);
    validation.set_required_spec_claims(&["exp", "iat", "sub", "iss"]);
    let data = jwt::decode::<LicenseJWTPayload>(token, &LICENSE_DECODING_KEY, &validation);
    let data = data.map_err(|err| match err.kind() {
        // Map json error (missing failed, parse error) as missing required claims.
        jwt::errors::ErrorKind::Json(err) => {
            jwt::errors::ErrorKind::MissingRequiredClaim(err.to_string())
        }
        _ => err.into_kind(),
    });
    Ok(data?.claims)
}

fn jwt_timestamp_to_utc(secs: i64) -> Result<DateTime<Utc>> {
    Ok(DateTime::from_timestamp(secs, 0).context("Timestamp is corrupt")?)
}

struct LicenseServiceImpl {
    db: DbConn,
}

impl LicenseServiceImpl {
    async fn make_community_license(&self) -> Result<LicenseInfo> {
        let seats_used = self.db.count_active_users().await?;
        let status = if seats_used > LicenseInfo::seat_limits_for_community_license() {
            LicenseStatus::SeatsExceeded
        } else {
            LicenseStatus::Ok
        };

        Ok(LicenseInfo {
            r#type: LicenseType::Community,
            status,
            seats: LicenseInfo::seat_limits_for_community_license() as i32,
            seats_used: seats_used as i32,
            issued_at: None,
            expires_at: None,
        }
        .guard_seat_limit())
    }

    async fn make_demo_license(&self) -> Result<LicenseInfo> {
        let seats_used = self.db.count_active_users().await? as i32;
        Ok(LicenseInfo {
            r#type: LicenseType::Enterprise,
            status: LicenseStatus::Ok,
            seats: 100,
            seats_used,
            issued_at: None,
            expires_at: None,
        })
    }
}

pub async fn new_license_service(db: DbConn) -> Result<impl LicenseService> {
    Ok(LicenseServiceImpl { db })
}

fn license_info_from_raw(raw: LicenseJWTPayload, seats_used: usize) -> Result<LicenseInfo> {
    let issued_at = jwt_timestamp_to_utc(raw.iat)?;
    let expires_at = jwt_timestamp_to_utc(raw.exp)?;

    let status = if expires_at < Utc::now() {
        LicenseStatus::Expired
    } else if seats_used > raw.num {
        LicenseStatus::SeatsExceeded
    } else {
        LicenseStatus::Ok
    };

    let license = LicenseInfo {
        r#type: raw.typ,
        status,
        seats: raw.num as i32,
        seats_used: seats_used as i32,
        issued_at: Some(issued_at),
        expires_at: Some(expires_at),
    }
    .guard_seat_limit();
    Ok(license)
}

#[async_trait]
impl LicenseService for LicenseServiceImpl {
    async fn read(&self) -> Result<LicenseInfo> {
        if is_demo_mode() {
            return self.make_demo_license().await;
        }

        let Some(license) = self.db.read_enterprise_license().await? else {
            return self.make_community_license().await;
        };
        let license =
            validate_license(&license).map_err(|e| anyhow!("License is corrupt: {e:?}"))?;
        let seats = self.db.count_active_users().await?;
        let license = license_info_from_raw(license, seats)?;

        Ok(license)
    }

    async fn update(&self, license: String) -> Result<()> {
        if is_demo_mode() {
            bail!("Modifying license is disabled in demo mode");
        }

        let raw = validate_license(&license).map_err(|_e| anyhow!("License is not valid"))?;
        let seats = self.db.count_active_users().await?;
        match license_info_from_raw(raw, seats)?.status {
            LicenseStatus::Ok => self.db.update_enterprise_license(Some(license)).await?,
            LicenseStatus::Expired => bail!("License is expired"),
            LicenseStatus::SeatsExceeded => {
                bail!("License doesn't contain sufficient number of seats")
            }
        };
        Ok(())
    }

    async fn reset(&self) -> Result<()> {
        self.db.update_enterprise_license(None).await?;
        Ok(())
    }
}

