use std::io::ErrorKind::Other;
use actix_session::Session;
use actix_web::{HttpResponse, web};
use jsonwebtoken::{Algorithm, decode, decode_header, DecodingKey, TokenData, Validation};
use jsonwebtoken::errors::{Error, ErrorKind};
use log::{debug, info};
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::{AuthorizationCode, AuthUrl, ClientId, ClientSecret, PkceCodeVerifier, RedirectUrl, TokenUrl};
use oauth2::reqwest::async_http_client;
use reqwest::header::LOCATION;
use serde::de::DeserializeOwned;
use tracing_attributes::instrument;
use crate::entities::{Config, ErrorInfo, JWKS, JWKSKeyItem, MyAppError, MyAppResult};
use crate::SESSION_KEY_ERROR;



pub const PAGE_PROFILE: &str = "/profile";
pub const PAGE_ERROR: &str = "/error";



///
/// Get JWKS Item by kid
///
#[instrument(level = "debug")]
pub fn get_jwks_item(jwks: &JWKS, kid: &str) -> Option<JWKSKeyItem> {
    for item in jwks.keys.iter() {
        let found_item = item
            .iter()
            .find(|&key| key.kid.clone().unwrap_or("".to_string()).eq(kid));
        if let Some(found_item) = found_item {
            return Some(found_item.clone());
        }
    }
    None
}

///
/// Function get code verifier
///
//#[instrument]
#[instrument(skip(session))]
pub fn get_code_verifier_from_session(
    session: &Session,
    key: String,
) -> MyAppResult<Option<PkceCodeVerifier>> {
    debug!(
        "call get_code_verifier_from_session [{:#?}]  with key = {}",
        session.entries(),
        key
    );
    if let Some(verifier) = session.get::<PkceCodeVerifier>(key.as_str()).unwrap() {
        debug!("Verifier : {:#?}", verifier.secret());
        return Ok(Some(verifier));
    }
    Err(MyAppError::new(format!("Key [{}] No Value ", key)))
}
///
/// Validate JWT Token
///
//#[instrument]
#[instrument(level = "debug")]
pub fn jwt_token_validation<T>(jwt_token: &str, jwks: &JWKS) -> Result<TokenData<T>, Error>
    where
        T: DeserializeOwned,
{
    let header = decode_header(jwt_token);
    match header {
        Ok(h) => match get_jwks_item(jwks, h.kid.unwrap().as_str()) {
            Some(item) => {
                debug!("Found JWKS Item : {:?}", item);
                let token = decode::<T>(
                    jwt_token,
                    &DecodingKey::from_rsa_components(
                        item.n.clone().unwrap().as_str(),
                        item.e.clone().unwrap().as_str(),
                    )
                        .unwrap(),
                    &Validation::new(Algorithm::RS256),
                );
                token
            }
            None => Err(jsonwebtoken::errors::Error::from(
                ErrorKind::InvalidAudience,
            )),
        },
        Err(e) => Err(e),
    }
}

///
/// Get Access Token
///
//#[instrument]
#[instrument(level = "debug")]
pub async fn get_access_token(
    config: &web::Data<Config>,
    auth_code: &str,
    code_verifier: &str,
) -> Result<BasicTokenResponse, std::io::Error> {
    let client = BasicClient::new(
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
        AuthUrl::new(
            config
                .open_id_config
                .clone()
                .unwrap()
                .authorization_endpoint
                .unwrap(),
        )
            .unwrap(),
        Some(
            TokenUrl::new(
                config
                    .open_id_config
                    .clone()
                    .unwrap()
                    .token_endpoint
                    .unwrap(),
            )
                .unwrap(),
        ),
    )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new(config.redirect.clone()).unwrap());
    info!("request access token ");
    let token_result = client
        .exchange_code(AuthorizationCode::new(auth_code.to_string()))
        .add_extra_param("code_verifier", code_verifier)
        .request_async(async_http_client)
        .await
        .map_err(|e| std::io::Error::new(Other, e.to_string()));
    //debug!("token result > {:#?}", token_result);
    token_result
}

///
///  redirect to error page
///
//#[instrument]
#[instrument(skip(session))]
pub fn redirect_to_error_page(session: &Session, error: &ErrorInfo) -> HttpResponse {
    session.insert(SESSION_KEY_ERROR, error).unwrap();
    HttpResponse::SeeOther()
        .insert_header((LOCATION, PAGE_ERROR))
        .finish()
}
///
/// redirect to page
///
//#[instrument]
#[instrument(skip(_session))]
pub fn redirect_to_page(_session: &Session, page: &str) -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header((LOCATION, page))
        .finish()
}