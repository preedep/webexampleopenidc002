use actix_files::Files;
use actix_session::config::PersistentSession;
use actix_session::storage::RedisActorSessionStore;
use actix_session::{Session, SessionMiddleware};
use actix_web::middleware::Logger;
use actix_web::web::{Data, Redirect};
use actix_web::{middleware, web, App, HttpResponse, HttpServer, Responder};

use actix_web::cookie::time::Duration;
use actix_web::cookie::SameSite;
use handlebars::Handlebars;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use log::{debug, error, info};
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, ResponseType, Scope, TokenResponse, TokenUrl,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt;

const SESSION_KEY_ID_TOKEN: &str = "ID_TOKEN_KEY";
const SESSION_KEY_ERROR: &str = "ERROR_KEY";
const SESSION_KEY_ACCESS_TOKEN: &str = "ACCESS_TOKEN";

const PAGE_PROFILE: &str = "/profile";
const PAGE_ERROR: &str = "/error";
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
    #[serde(rename = "xms_pl")]
    pub xms_pl: Option<String>,
    #[serde(rename = "xms_tpl")]
    pub xms_tpl: Option<String>,
    pub department: Option<String>,
    pub companyname: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorInfo {
    #[serde(with = "http_serde::status_code")]
    http_status_code: StatusCode,
    http_status_message: Option<String>,
    error_message: Option<String>,
}

impl ErrorInfo {
    fn new(http_status_code: StatusCode) -> Self {
        ErrorInfo {
            http_status_code,
            http_status_message: None,
            error_message: None,
        }
    }
    fn set_error_message(&mut self, error_message: String) -> &Self {
        self.error_message = Some(error_message);
        self
    }
    fn get_http_status_message(&self) -> String {
        self.http_status_code.to_string()
    }
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct GraphMe {
    #[serde(rename = "companyName")]
    company_name: String,
    #[serde(rename = "department")]
    department: String,
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(rename = "employeeId")]
    employee_id: String,
    #[serde(rename = "jwt_token_raw")]
    jwt_token_raw: Option<String>,
}
#[derive(Debug, Clone)]
struct Config {
    redis_url: String,
    redis_auth_key: String,
    tenant_id: String,
    default_page: String,
    redirect: String,
    client_id: String,
    client_secret: String,
    open_id_config: Option<OpenIDConfigurationV2>,
}

impl Config {
    fn new(
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
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginQueryString {
    #[serde(rename(deserialize = "response_type"))]
    response_type: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct ResponseAuthorized {
    #[serde(rename(deserialize = "code"))]
    code: Option<String>,
    #[serde(rename(deserialize = "session_state"))]
    session_state: Option<String>,
    #[serde(rename(deserialize = "state"))]
    state: Option<String>,
    #[serde(rename(deserialize = "id_token"))]
    id_token: Option<String>,
    #[serde(rename(deserialize = "error"))]
    error: Option<String>,
    #[serde(rename(deserialize = "error_description"))]
    error_description: Option<String>,
}

type MyAppResult<T> = std::result::Result<T, MyAppError>;
#[derive(Debug, Clone, Serialize)]
struct MyAppError {
    error_message: String,
}
impl MyAppError {
    fn new(error_message: String) -> Self {
        MyAppError { error_message }
    }
}
impl fmt::Display for MyAppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "App Error {}", self.error_message)
    }
}

///
/// Function get code verifier
///
fn get_code_verifier_from_session(
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
/// Logout
///
async fn logout(
    session: Session,
    _params: web::Query<ResponseAuthorized>,
    data: web::Data<Config>,
) -> impl Responder {
    let sign_out_url = format!(
        "{}?post_logout_redirect_uri={}",
        data.open_id_config
            .clone()
            .unwrap()
            .end_session_endpoint
            .unwrap(),
        urlencoding::encode(data.default_page.clone().as_str())
    );
    debug!("redirect to url > {}", sign_out_url);
    session.purge();
    debug!("Session was purged");
    //let result = Uri::from_str(sign_out_url.as_str());
    Redirect::to(sign_out_url).permanent()
}
///
/// callback page with HTTP GET
///
async fn get_callback(
    session: Session,
    params: web::Query<ResponseAuthorized>,
    data: web::Data<Config>,
) -> impl Responder {
    callback(session, params.0, data).await
}
///
/// callback page with HTTP POST
///
async fn post_callback(
    session: Session,
    params: web::Form<ResponseAuthorized>,
    data: web::Data<Config>,
) -> impl Responder {
    callback(session, params.0, data).await
}
///
/// Callback
///
async fn callback(
    session: Session,
    params: ResponseAuthorized,
    data: web::Data<Config>,
) -> impl Responder {
    debug!("Callback > {:#?}", params);
    match params.state {
        None => {
            session
                .insert(
                    SESSION_KEY_ERROR,
                    ErrorInfo::new(StatusCode::BAD_REQUEST)
                        .set_error_message(format!("{}", "State Is None")),
                )
                .unwrap();
            return Redirect::to(PAGE_ERROR).permanent();
        }
        Some(_) => {}
    }

    return match get_code_verifier_from_session(&session, params.state.clone().unwrap()) {
        Ok(verifier) => {
            if params.id_token.is_some() {
                // Have ID Token
                let jwt_id_token = params.id_token.clone().unwrap();
                let key = DecodingKey::from_secret(&[]);
                //let key = DecodingKey::from_rsa_pem(pem_bytes);
                let mut validation = Validation::new(Algorithm::RS256);
                validation.insecure_disable_signature_validation();
                let data = decode::<JwtPayloadIDToken>(jwt_id_token.as_str(), &key, &validation);
                match session.insert(SESSION_KEY_ID_TOKEN, data.unwrap().claims) {
                    Ok(_) => {
                        debug!("Insert ID_TOKEN_KEY Successful ");
                        Redirect::to(PAGE_PROFILE).permanent()
                    }
                    Err(e) => {
                        error!("Insert Session Error {}", e);
                        session
                            .insert(
                                SESSION_KEY_ERROR,
                                ErrorInfo::new(StatusCode::UNAUTHORIZED)
                                    .set_error_message(format!("{}", e)),
                            )
                            .unwrap();
                        Redirect::to(PAGE_ERROR).permanent()
                    }
                }
            } else if params.code.is_some() {
                // Have Auth Codd
                let client = BasicClient::new(
                    ClientId::new(data.client_id.clone()),
                    Some(ClientSecret::new(data.client_secret.clone())),
                    AuthUrl::new(
                        data.open_id_config
                            .clone()
                            .unwrap()
                            .authorization_endpoint
                            .unwrap(),
                    )
                    .unwrap(),
                    Some(
                        TokenUrl::new(data.open_id_config.clone().unwrap().token_endpoint.unwrap())
                            .unwrap(),
                    ),
                )
                // Set the URL the user will be redirected to after the authorization process.
                .set_redirect_uri(RedirectUrl::new(data.redirect.clone()).unwrap());

                info!("request access token ");
                let token_result = client
                    .exchange_code(AuthorizationCode::new(params.code.unwrap()))
                    .add_extra_param("code_verifier", verifier.unwrap().secret())
                    //.request(http_client);
                    .request_async(async_http_client)
                    .await;
                debug!("token result > {:#?}", token_result);
                match session.insert(SESSION_KEY_ACCESS_TOKEN, token_result.unwrap()) {
                    Ok(_) => {
                        debug!("Insert session [{}] complete", SESSION_KEY_ACCESS_TOKEN);
                    }
                    Err(e) => {
                        error!("Insert session [{}] error {}", SESSION_KEY_ACCESS_TOKEN, e);
                    }
                }
                debug!("Handle grant auth code");
                Redirect::to(PAGE_PROFILE).permanent()
            } else {
                // Unknown type
                session
                    .insert(
                        SESSION_KEY_ERROR,
                        ErrorInfo::new(StatusCode::BAD_REQUEST)
                            .set_error_message(format!("{}", "Grant type unknown")),
                    )
                    .unwrap();
                Redirect::to(PAGE_ERROR).permanent()
            }
        }
        Err(e) => {
            error!("Session Error {}", e);
            session
                .insert(
                    SESSION_KEY_ERROR,
                    ErrorInfo::new(StatusCode::UNAUTHORIZED).set_error_message(format!("{}", e)),
                )
                .unwrap();
            Redirect::to(PAGE_ERROR).permanent()
        }
    };
}
///
///  Login
///
async fn login(
    session: Session,
    params: web::Query<LoginQueryString>,
    data: web::Data<Config>,
) -> impl Responder {
    debug!("params : {:#?}", params);

    let response_type = params.0.response_type.unwrap_or("code".to_string());
    debug!("Get response_type {}", response_type);

    if !data
        .open_id_config
        .clone()
        .unwrap()
        .response_types_supported
        .unwrap()
        .contains(&response_type.to_owned())
    {
        error!("Response type = {} Not support", response_type.clone());
    }

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    debug!(
        "PKCE challenge : {:?} \r\n ,\
            PKCE verifier {:?}",
        pkce_challenge, pkce_verifier
    );

    let client = BasicClient::new(
        ClientId::new(data.client_id.clone()),
        Some(ClientSecret::new(data.client_secret.clone())),
        AuthUrl::new(
            data.open_id_config
                .clone()
                .unwrap()
                .authorization_endpoint
                .unwrap(),
        )
        .unwrap(),
        None,
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new(data.redirect.clone()).unwrap());
    let mut auth_req = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("User.Read".to_string()))
        .set_pkce_challenge(pkce_challenge);

    let mut response_mode = "query";
    if response_type.eq("id_token") {
        response_mode = "form_post";
        auth_req = auth_req.add_extra_param("nonce", "1234234233232322222")
    }
    auth_req = auth_req.add_extra_param("response_mode", response_mode);
    let res_type = ResponseType::new(response_type);
    auth_req = auth_req.set_response_type(&res_type);
    let (auth_url, csrf_token) = auth_req.url();

    debug!("csrf_token = {}", csrf_token.secret());
    let auth_url = format!("{}", auth_url);
    debug!("Url : {}", auth_url.clone());

    let s = session.insert(csrf_token.secret().as_str(), pkce_verifier);

    match s {
        Ok(_) => {
            debug!(
                "save session complete , Status :> {:#?}\r\n{:#?}",
                session.status(),
                session.entries()
            );
            debug!("Try to redirect");
            Redirect::to(auth_url).permanent()
        }
        Err(e) => {
            error!("save session error : {}", e);
            session
                .insert(
                    SESSION_KEY_ERROR,
                    ErrorInfo::new(StatusCode::UNAUTHORIZED).set_error_message(format!("{}", e)),
                )
                .unwrap();
            Redirect::to(PAGE_ERROR).permanent()
        }
    }
}
///
///  main page
///
async fn index(
    session: Session,
    data: web::Data<Config>,
    hb: web::Data<Handlebars<'_>>,
) -> impl Responder {
    //session.insert("test","test").unwrap();
    //NamedFile::open_async("./static/index.html").await
    let data = json!({
            "Name": "",
        }
    );
    let body = hb.render("index", &data).unwrap();
    HttpResponse::Ok().body(body)
}
///
///  profile page
///
async fn profile(
    session: Session,
    data: web::Data<Config>,
    hb: web::Data<Handlebars<'_>>,
) -> impl Responder {
    let basic_token = session
        .get::<BasicTokenResponse>(SESSION_KEY_ACCESS_TOKEN)
        .unwrap();
    return match basic_token {
        None => {
            let token = session
                .get::<JwtPayloadIDToken>(SESSION_KEY_ID_TOKEN)
                .unwrap();
            match token {
                None => HttpResponse::InternalServerError().finish(),
                Some(jwt) => {
                    debug!("JWT ID Token : {:#?}", jwt);

                    let mut user = GraphMe {
                        company_name: jwt.to_owned().companyname.unwrap_or("".to_string()),
                        department: jwt.to_owned().department.unwrap_or("".to_string()),
                        display_name: jwt.name.to_owned().unwrap_or("".to_string()),
                        employee_id: "".to_string(),
                        jwt_token_raw: Some(serde_json::to_string_pretty(&jwt.to_owned()).unwrap()),
                    };

                    let body = hb.render("profile", &user).unwrap();
                    HttpResponse::Ok().body(body)
                }
            }
        }
        Some(token) => {
            let url = data.open_id_config.clone().unwrap().msgraph_host.unwrap();
            let url = format!(
                "https://{}/v1.0/me?$select=displayName,department,employeeId,companyName",
                url
            );
            let client = reqwest::Client::new();
            let res_user_info = client
                .get(url)
                .header(
                    "Authorization",
                    format!("Bearer {}", token.access_token().secret()),
                )
                .header("Content-Type", "application/json")
                .send()
                .await;

            let res_me = res_user_info.unwrap().json::<GraphMe>().await;
            match res_me {
                Ok(user) => {
                    let body = hb.render("profile", &user).unwrap();
                    HttpResponse::Ok().body(body)
                }
                Err(e) => HttpResponse::InternalServerError().body(format!("{}", e)),
            }
        }
    };
    //let body = hb.render("profile", &data).unwrap();
}
///
///  profile page
///
async fn error_display(
    session: Session,
    data: web::Data<Config>,
    hb: web::Data<Handlebars<'_>>,
) -> impl Responder {
    let data = json!({
            "Name": "Nick",
        }
    );
    let error = session.get::<ErrorInfo>(SESSION_KEY_ERROR);
    match error {
        Ok(r) => {
            if r.is_some() {
                let body = hb.render("error", &r.unwrap()).unwrap();
                return HttpResponse::Ok().body(body);
            }
        }
        Err(e) => {
            error!("Session Error {}", e)
        }
    }
    let body = hb.render("error", &data).unwrap();
    HttpResponse::Ok().body(body)
}
///
/// Main app
///
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();
    info!("Server starting...");
    //
    //  Load environment variable
    //
    let redis_url = std::env::var("REDIS_URL").unwrap();
    let redis_auth_key = std::env::var("REDIS_AUTH_KEY").unwrap();
    let tenant_id = std::env::var("TENANT_ID").unwrap();
    let default_page = std::env::var("DEFAULT_PAGE").unwrap();
    let redirect_url = std::env::var("REDIRECT_URL").unwrap();
    let client_id = std::env::var("CLIENT_ID").unwrap();
    let client_secret = std::env::var("CLIENT_SECRET").unwrap();
    let cookie_ssl = std::env::var("COOKIE_SSL").unwrap_or("false".to_string());

    let use_cookie_ssl: bool = match cookie_ssl.as_str() {
        "false" => false,
        "true" => true,
        _ => false,
    };

    let mut config = Config::new(
        redis_url,
        redis_auth_key,
        tenant_id,
        default_page,
        redirect_url,
        client_id,
        client_secret,
    );

    debug!("Get configuration from env complete");
    debug!("Cookie SSL : {}", use_cookie_ssl);

    //
    // Get azure ad meta data
    //
    let url_openid_config = format!(
        r#"https://login.microsoftonline.com/{:1}/v2.0/.well-known/openid-configuration?appid={:2}"#,
        config.to_owned().tenant_id,
        config.to_owned().client_id
    );

    info!("url validation : {}", url_openid_config);
    let meta_azure_ad = reqwest::get(url_openid_config)
        .await
        .unwrap()
        .json::<OpenIDConfigurationV2>()
        .await;
    match meta_azure_ad {
        Ok(cnf) => {
            debug!("Meta data : {:#?}", cnf);
            config.open_id_config = Some(cnf);
        }
        Err(e) => {
            error!("Get meta error : {}", e);
        }
    }
    let private_key = actix_web::cookie::Key::generate();

    //let redis_connection = config.clone().redis_url.replace("x","");
    //let redis_connection = redis_connection.clone().replace("y",config.clone().redis_auth_key.as_str());
    let redis_connection = config.clone().redis_url.replace("redis://", "");
    debug!("Redis connection > {}", redis_connection.to_owned());

    let mut hbars = Handlebars::new();
    hbars
        .register_templates_directory(".html", "./static/")
        .unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(config.clone()))
            .app_data(Data::new(hbars.clone()))
            .wrap(middleware::DefaultHeaders::new().add(("Dev-X-Version", "0.1")))
            .wrap(Logger::default())
            .wrap(Logger::new(
                r#"%a %t "%r" %s %b "%{Referer}i" "%{User-Agent}i" %T"#,
            ))
            .wrap(
                SessionMiddleware::builder(
                    RedisActorSessionStore::new(redis_connection.to_owned()),
                    private_key.clone(),
                )
                .cookie_name("COOK_WEB_EXAMPLE_KEY".to_string())
                .session_lifecycle(
                    PersistentSession::default().session_ttl(Duration::days(1 /*1 day*/)),
                )
                .cookie_secure(use_cookie_ssl)
                .cookie_same_site(SameSite::None)
                .cookie_http_only(false)
                .build(),
            )
            //.wrap(RedirectHttps::with_hsts(StrictTransportSecurity::default()))
            .route("/", web::get().to(index))
            .route("/login", web::get().to(login))
            .service(
                web::resource("/callback")
                    .route(web::get().to(get_callback))
                    .route(web::post().to(post_callback)),
            )
            .service(
                web::resource("/profile")
                    .route(web::get().to(profile))
                    .route(web::post().to(profile)),
            )
            .service(
                web::resource("/error")
                    .route(web::get().to(error_display))
                    .route(web::post().to(error_display)),
            )
            .route("/logout", web::get().to(logout))
            .service(Files::new("/static", "static").prefer_utf8(true))
    })
    // .keep_alive(KeepAlive::from(std::time::Duration::from_millis(10 * 1000)))
    .workers(20)
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
