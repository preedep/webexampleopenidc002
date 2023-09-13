use actix_web::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::fmt;

///
/// Open ID Configuration
///
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenIDConfigurationV2 {
    #[serde(rename = "token_endpoint")]
    pub token_endpoint: Option<String>,
    #[serde(rename = "token_endpoint_auth_methods_supported")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(rename = "jwks_uri")]
    pub jwks_uri: Option<String>,
    #[serde(rename = "response_modes_supported")]
    pub response_modes_supported: Option<Vec<String>>,
    #[serde(rename = "subject_types_supported")]
    pub subject_types_supported: Option<Vec<String>>,
    #[serde(rename = "id_token_signing_alg_values_supported")]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(rename = "response_types_supported")]
    pub response_types_supported: Option<Vec<String>>,
    #[serde(rename = "scopes_supported")]
    pub scopes_supported: Option<Vec<String>>,
    pub issuer: Option<String>,
    #[serde(rename = "request_uri_parameter_supported")]
    pub request_uri_parameter_supported: Option<bool>,
    #[serde(rename = "userinfo_endpoint")]
    pub userinfo_endpoint: Option<String>,
    #[serde(rename = "authorization_endpoint")]
    pub authorization_endpoint: Option<String>,
    #[serde(rename = "device_authorization_endpoint")]
    pub device_authorization_endpoint: Option<String>,
    #[serde(rename = "http_logout_supported")]
    pub http_logout_supported: Option<bool>,
    #[serde(rename = "frontchannel_logout_supported")]
    pub frontchannel_logout_supported: Option<bool>,
    #[serde(rename = "end_session_endpoint")]
    pub end_session_endpoint: Option<String>,
    #[serde(rename = "claims_supported")]
    pub claims_supported: Option<Vec<String>>,
    #[serde(rename = "kerberos_endpoint")]
    pub kerberos_endpoint: Option<String>,
    #[serde(rename = "tenant_region_scope")]
    pub tenant_region_scope: Option<String>,
    #[serde(rename = "cloud_instance_name")]
    pub cloud_instance_name: Option<String>,
    #[serde(rename = "cloud_graph_host_name")]
    pub cloud_graph_host_name: Option<String>,
    #[serde(rename = "msgraph_host")]
    pub msgraph_host: Option<String>,
    #[serde(rename = "rbac_url")]
    pub rbac_url: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtPayloadIDToken {
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub exp: Option<i64>,
    pub acct: Option<i64>,
    pub acrs: Option<Vec<String>>,
    pub aio: Option<String>,
    #[serde(rename = "auth_time")]
    pub auth_time: Option<i64>,
    pub ctry: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "family_name")]
    pub family_name: Option<String>,
    #[serde(rename = "given_name")]
    pub given_name: Option<String>,
    pub groups: Option<Vec<String>>,
    pub idp: Option<String>,
    pub ipaddr: Option<String>,
    #[serde(rename = "login_hint")]
    pub login_hint: Option<String>,
    pub name: Option<String>,
    pub nonce: Option<String>,
    pub oid: Option<String>,
    #[serde(rename = "preferred_username")]
    pub preferred_username: Option<String>,
    pub rh: Option<String>,
    pub sid: Option<String>,
    pub sub: Option<String>,
    #[serde(rename = "tenant_ctry")]
    pub tenant_ctry: Option<String>,
    #[serde(rename = "tenant_region_scope")]
    pub tenant_region_scope: Option<String>,
    pub tid: Option<String>,
    pub uti: Option<String>,
    pub ver: Option<String>,
    pub wids: Option<Vec<String>>,
    #[serde(rename = "xms_pl")]
    pub xms_pl: Option<String>,
    #[serde(rename = "xms_tpl")]
    pub xms_tpl: Option<String>,
    pub department: Option<String>,
    pub companyname: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JWKS {
    pub keys: Option<Vec<JWKSKeyItem>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JWKSKeyItem {
    pub kty: Option<String>,
    #[serde(rename = "use")]
    pub use_field: Option<String>,
    pub kid: Option<String>,
    pub x5t: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub x5c: Option<Vec<String>>,
    pub issuer: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorInfo {
    #[serde(with = "http_serde::status_code")]
    pub http_status_code: StatusCode,
    pub http_status_message: Option<String>,
    pub error_message: Option<String>,
}

impl ErrorInfo {
    pub fn new(http_status_code: StatusCode) -> Self {
        ErrorInfo {
            http_status_code,
            http_status_message: None,
            error_message: None,
        }
    }
    pub fn set_error_message(&mut self, error_message: String) -> &Self {
        self.error_message = Some(error_message);
        self
    }
    pub fn get_http_status_message(&self) -> String {
        self.http_status_code.to_string()
    }
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GraphMe {
    #[serde(rename = "companyName")]
    pub company_name: Option<String>,
    #[serde(rename = "department")]
    pub department: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "employeeId")]
    pub employee_id: Option<String>,
    #[serde(rename = "jwt_token_raw")]
    pub jwt_token_raw: Option<String>,
    #[serde(rename = "access_token")]
    pub access_token: Option<String>,
    #[serde(rename = "ping_url")]
    pub ping_url: Option<String>,
}
#[derive(Debug, Clone)]
pub struct Config {
    pub redis_url: String,
    pub redis_auth_key: String,
    pub tenant_id: String,
    pub default_page: String,
    pub redirect: String,
    pub client_id: String,
    pub client_secret: String,
    pub open_id_config: Option<OpenIDConfigurationV2>,
    pub jwks: Option<JWKS>,
    pub ping_url: Option<String>,
}

impl Config {
    pub fn new(
        redis_url: String,
        redis_auth_key: String,
        tenant_id: String,
        default_page: String,
        redirect: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        Config {
            redis_url,
            redis_auth_key,
            tenant_id,
            default_page,
            redirect,
            client_id,
            client_secret,
            open_id_config: None,
            jwks: None,
            ping_url: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginQueryString {
    #[serde(rename(deserialize = "response_type"))]
    pub response_type: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct ResponseAuthorized {
    #[serde(rename(deserialize = "code"))]
    pub code: Option<String>,
    #[serde(rename(deserialize = "session_state"))]
    pub session_state: Option<String>,
    #[serde(rename(deserialize = "state"))]
    pub state: Option<String>,
    #[serde(rename(deserialize = "id_token"))]
    pub id_token: Option<String>,
    #[serde(rename(deserialize = "error"))]
    pub error: Option<String>,
    #[serde(rename(deserialize = "error_description"))]
    pub error_description: Option<String>,
    #[serde(rename(deserialize = "access_token"))]
    pub access_token: Option<String>,
    #[serde(rename(deserialize = "token_type"))]
    pub token_type: Option<String>,
    #[serde(rename(deserialize = "scope"))]
    pub scope: Option<String>,
    #[serde(rename(deserialize = "expires_in"))]
    pub expires_in: Option<i64>,
}

pub type MyAppResult<T> = Result<T, MyAppError>;
#[derive(Debug, Clone, Serialize)]
pub struct MyAppError {
    pub error_message: String,
}
impl MyAppError {
    pub fn new(error_message: String) -> Self {
        MyAppError { error_message }
    }
}
impl fmt::Display for MyAppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "App Error {}", self.error_message)
    }
}
