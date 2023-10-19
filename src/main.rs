use actix_files::Files;
use actix_session::{Session, SessionMiddleware};
use actix_session::config::PersistentSession;
use actix_session::storage::RedisActorSessionStore;
use actix_web::{App, cookie, HttpResponse, HttpServer, middleware, Responder, web};
use actix_web::cookie::SameSite;
use actix_web::cookie::time::Duration;
use actix_web::dev::Service as _;
use actix_web::middleware::Logger;
use actix_web::web::Data;
use actix_web_opentelemetry::RequestTracing;
use futures_util::future::FutureExt;
use handlebars::{Context, Handlebars, Helper, HelperResult, Output, RenderContext, RenderError};
use jsonwebtoken::{Algorithm, decode, DecodingKey, Validation};
use log::{debug, error, info};
use oauth2::{
    AccessToken, AuthUrl, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    PkceCodeChallenge, RedirectUrl, ResponseType, Scope, TokenResponse,
};
use oauth2::basic::{BasicClient, BasicTokenResponse, BasicTokenType};
use oauth2::reqwest::async_http_client;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::io::ErrorKind::Other;
use tracing::Span;
use tracing_actix_web::TracingLogger;
use tracing_attributes::instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{layer::SubscriberExt, Registry};

use crate::entities::*;
use crate::utils::*;

mod entities;
mod utils;

const SESSION_KEY_ID_TOKEN: &str = "ID_TOKEN_KEY";
const SESSION_KEY_ERROR: &str = "ERROR_KEY";
const SESSION_KEY_ACCESS_TOKEN: &str = "ACCESS_TOKEN";

///
/// Logout
///
//#[instrument]
#[instrument(skip(session))]
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
    redirect_to_page(&session, sign_out_url.as_str())
}
///
/// callback page with HTTP GET
///
//#[instrument]
#[instrument(skip(session))]
async fn get_callback(
    session: Session,
    params: web::Query<ResponseAuthorized>,
    config: web::Data<Config>,
) -> impl Responder {
    callback(session, params.0, config).await
}
///
/// callback page with HTTP POST
///
//#[instrument]
#[instrument(skip(session))]
async fn post_callback(
    session: Session,
    params: web::Form<ResponseAuthorized>,
    config: web::Data<Config>,
) -> impl Responder {
    callback(session, params.0, config).await
}

///
/// Callback
///
//#[instrument]
#[instrument(skip(session))]
async fn callback(
    session: Session,
    params: ResponseAuthorized,
    config: web::Data<Config>,
) -> HttpResponse {
    debug!("Callback > {:#?}", params);
    if params.state.is_none() {
        return redirect_to_error_page(
            &session,
            &ErrorInfo::new(StatusCode::BAD_REQUEST)
                .set_error_message(format!("{}", "State Is None")),
        );
    }
    return match get_code_verifier_from_session(&session, params.state.clone().unwrap()) {
        Ok(verifier) => {
            if params.id_token.is_some() && params.access_token.is_some() {
                //id_token + access token
                //verify id_token
                let result = jwt_token_validation::<JwtPayloadIDToken>(
                    &params.id_token.clone().unwrap(),
                    &config.jwks.clone().unwrap(),
                );
                match result {
                    Ok(token) => {
                        let _ = session.insert(SESSION_KEY_ID_TOKEN, token.claims);
                        debug!("Insert ID_TOKEN_KEY Successful ");
                        let _ = session
                            .insert(
                                SESSION_KEY_ACCESS_TOKEN,
                                BasicTokenResponse::new(
                                    AccessToken::new(params.access_token.unwrap()),
                                    BasicTokenType::Bearer,
                                    EmptyExtraTokenFields {},
                                ),
                            )
                            .unwrap();
                        debug!("Insert ACCESS_KEY Successful ");
                        redirect_to_page(&session, PAGE_PROFILE)
                    }
                    Err(e) => redirect_to_error_page(
                        &session,
                        &ErrorInfo::new(StatusCode::BAD_REQUEST)
                            .set_error_message(format!("{}", e)),
                    ),
                }
            } else if params.id_token.is_some() && params.code.is_some() {
                //id_token + auth code
                //verify id_token
                let result = jwt_token_validation::<JwtPayloadIDToken>(
                    &params.id_token.clone().unwrap(),
                    &config.jwks.clone().unwrap(),
                );
                match result {
                    Ok(token) => {
                        let _ = session.insert(SESSION_KEY_ID_TOKEN, token.claims);
                        debug!("Insert ID_TOKEN_KEY Successful ");
                        let result_access = get_access_token(
                            &config,
                            params.code.unwrap().as_str(),
                            verifier.unwrap().secret().as_str(),
                        )
                        .await;
                        match result_access {
                            Ok(token) => {
                                let _ = session.insert(SESSION_KEY_ACCESS_TOKEN, token);
                                debug!("Insert ACCESS_KEY Successful ");
                                //Redirect::to(PAGE_PROFILE).permanent()
                                redirect_to_page(&session, PAGE_PROFILE)
                            }
                            Err(e) => redirect_to_error_page(
                                &session,
                                &ErrorInfo::new(StatusCode::BAD_REQUEST)
                                    .set_error_message(format!("{}", e)),
                            ),
                        }
                    }
                    Err(e) => redirect_to_error_page(
                        &session,
                        &ErrorInfo::new(StatusCode::BAD_REQUEST)
                            .set_error_message(format!("{}", e)),
                    ),
                }
            } else if params.id_token.is_some() {
                //id_token
                //verify ID_TOKEN signature
                //example for verify JWT signature
                let result = jwt_token_validation::<JwtPayloadIDToken>(
                    &params.id_token.clone().unwrap(),
                    &config.jwks.clone().unwrap(),
                );
                match result {
                    Ok(token) => {
                        let _ = session.insert(SESSION_KEY_ID_TOKEN, token.claims);
                        debug!("Insert ID_TOKEN_KEY Successful ");
                        //Redirect::to(PAGE_PROFILE).permanent()
                        redirect_to_page(&session, PAGE_PROFILE)
                    }
                    Err(e) => redirect_to_error_page(
                        &session,
                        &ErrorInfo::new(StatusCode::BAD_REQUEST)
                            .set_error_message(format!("{}", e)),
                    ),
                }
                ////////////////////////////////
            } else if params.code.is_some() {
                //code
                let result_access = get_access_token(
                    &config,
                    params.code.unwrap().as_str(),
                    verifier.unwrap().secret().as_str(),
                )
                .await;
                match result_access {
                    Ok(token) => {
                        let _ = session.insert(SESSION_KEY_ACCESS_TOKEN, token);
                        debug!("Insert ACCESS_KEY Successful ");
                        redirect_to_page(&session, PAGE_PROFILE)
                    }
                    Err(e) => redirect_to_error_page(
                        &session,
                        &ErrorInfo::new(StatusCode::BAD_REQUEST)
                            .set_error_message(format!("{}", e)),
                    ),
                }
            } else {
                redirect_to_error_page(
                    &session,
                    &ErrorInfo::new(StatusCode::BAD_REQUEST)
                        .set_error_message(format!("{}", "Grant type unknown")),
                )
            }
        }
        Err(e) => {
            error!("Session Error {}", e);
            redirect_to_error_page(
                &session,
                &ErrorInfo::new(StatusCode::UNAUTHORIZED).set_error_message(format!("{}", e)),
            )
        }
    };
}
///
///  Login
///
//#[instrument]
#[instrument(skip(session))]
async fn login(
    session: Session,
    params: web::Query<LoginQueryString>,
    data: web::Data<Config>,
) -> impl Responder {
    debug!("params : {:#?}", params);

    let response_types = params.0.response_type.unwrap_or("code".to_string());
    //debug!("Get response_type {}", response_type);

    if !data
        .open_id_config
        .clone()
        .unwrap()
        .response_types_supported
        .unwrap()
        .contains(&response_types.to_owned())
    {
        error!("Response type = {} Not support", response_types.clone());
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
        .add_scope(Scope::new("offline_access".to_string()))
        .set_pkce_challenge(pkce_challenge);

    let response_type_lists = response_types.split(" ");

    let mut response_mode = "query";
    let mut has_code = false;
    for response_type in response_type_lists.into_iter() {
        if response_type.eq("code") {
            if !response_types.contains("id_token") {
                auth_req = auth_req.add_scope(Scope::new(
                    "https://graph.microsoft.com/.default".to_string(),
                ));
            }
            has_code = true;
        }
        if response_type.eq("id_token") {
            response_mode = "form_post";
            auth_req = auth_req
                .add_extra_param("nonce", "1234234233232322222")
                .add_scope(Scope::new("openid".to_string()))
                .add_scope(Scope::new("email".to_string()))
                .add_scope(Scope::new("profile".to_string()));
            if has_code {
                auth_req =
                    auth_req.add_scope(Scope::new(data.api_permission_scope.clone().unwrap()));
            }
        }
        if response_type.eq("token") {
            //access token from implicit flow
            auth_req = auth_req.add_scope(Scope::new(data.api_permission_scope.clone().unwrap()));
        }
    }
    auth_req = auth_req.add_extra_param("response_mode", response_mode);
    let res_type = ResponseType::new(response_types);
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
            //debug!("Try to redirect");
            //Redirect::to(auth_url).permanent()
            redirect_to_page(&session, auth_url.as_str())
        }
        Err(e) => {
            error!("save session error : {}", e);
            redirect_to_error_page(
                &session,
                &ErrorInfo::new(StatusCode::UNAUTHORIZED).set_error_message(format!("{}", e)),
            )
        }
    }
}
///
///  main page
///
//#[instrument]
#[instrument(skip(_session))]
async fn index(
    _session: Session,
    _data: web::Data<Config>,
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
//#[instrument]
#[instrument(skip(session))]
async fn profile(
    session: Session,
    data: web::Data<Config>,
    hb: web::Data<Handlebars<'_>>,
) -> impl Responder {
    let id_token = session
        .get::<JwtPayloadIDToken>(SESSION_KEY_ID_TOKEN)
        .unwrap();
    return match id_token {
        None => {
            //auth code flow
            let access_token = session
                .get::<BasicTokenResponse>(SESSION_KEY_ACCESS_TOKEN)
                .unwrap();
            //
            //  Get Access Token
            //
            let access_token = access_token.unwrap();

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
                    format!("Bearer {}", access_token.access_token().secret()),
                )
                .header("Content-Type", "application/json")
                .send()
                .await;

            let res_me = res_user_info.unwrap().json::<GraphMe>().await;
            let mut user = res_me.unwrap();
            user.ping_url = Some(data.to_owned().ping_url.clone().unwrap());
            // This access token for Graph API requests
            user.access_token = None; //Some(access_token.access_token().secret().to_string());
            user.jwt_token_raw = Some(serde_json::to_string(&user.to_owned()).unwrap());
            let body = hb.render("profile", &user).unwrap();
            HttpResponse::Ok().body(body)
        }
        Some(id_token) => {
            let access_token = session
                .get::<BasicTokenResponse>(SESSION_KEY_ACCESS_TOKEN)
                .unwrap();
            let mut user = GraphMe {
                company_name: None,
                department: None,
                display_name: None,
                employee_id: None,
                office_location: None,
                jwt_token_raw: None,
                jwt_access_token_raw: None,
                access_token: None,
                ping_url: None,
            };
            debug!("JWT ID Token : {:#?}", id_token);
            user.employee_id = Some(id_token.to_owned().employee_id.unwrap_or("".to_string()));
            user.company_name = Some(id_token.to_owned().companyname.unwrap_or("".to_string()));
            user.department = Some(id_token.to_owned().department.unwrap_or("".to_string()));
            user.display_name = Some(id_token.to_owned().name.unwrap_or("".to_string()));
            user.office_location =
                Some(id_token.to_owned().officelocation.unwrap_or("".to_string()));

            user.jwt_token_raw = Some(serde_json::to_string(&id_token.to_owned()).unwrap());
            user.ping_url = Some(data.to_owned().ping_url.clone().unwrap());
            if access_token.is_some() {
                //  IT Token + Access Token
                let access_token = access_token.unwrap();
                user.access_token = Some(access_token.access_token().secret().to_string());
                let access_token = user.access_token.clone().unwrap();
                let key = DecodingKey::from_secret(&[]);
                let mut validation = Validation::new(Algorithm::RS256);
                validation.insecure_disable_signature_validation();
                let data = decode::<JwtAccessToken>(access_token.as_str(), &key, &validation);
                user.jwt_access_token_raw =
                    Some(serde_json::to_string(&data.unwrap().claims.to_owned()).unwrap());
            }
            let body = hb.render("profile", &user).unwrap();
            HttpResponse::Ok().body(body)
        }
    };
}
///
///  profile page
///
//#[instrument]
#[instrument(skip(session))]
async fn error_display(
    session: Session,
    _data: web::Data<Config>,
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
//#[instrument]
fn middle_ware_session(
    redis_connection: &str,
    private_key: cookie::Key,
    use_cookie_ssl: bool,
) -> SessionMiddleware<RedisActorSessionStore> {
    SessionMiddleware::builder(RedisActorSessionStore::new(redis_connection), private_key)
        .cookie_name("APP_AUTHEN_SESSION_KEY".to_string())
        .session_lifecycle(
            PersistentSession::default().session_ttl(Duration::minutes(15 /*1 day*/)),
        )
        .cookie_secure(use_cookie_ssl)
        //.cookie_content_security(CookieContentSecurity::Private)
        .cookie_same_site(SameSite::None)
        .cookie_http_only(true)
        .build()
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
    let app_insights_connection_str = std::env::var("APPLICATIONINSIGHTS_CON_STRING");

    let redis_url = std::env::var("REDIS_URL").unwrap();
    let redis_auth_key = std::env::var("REDIS_AUTH_KEY").unwrap();
    let tenant_id = std::env::var("TENANT_ID").unwrap();
    let default_page = std::env::var("DEFAULT_PAGE").unwrap();
    let redirect_url = std::env::var("REDIRECT_URL").unwrap();
    let client_id = std::env::var("CLIENT_ID").unwrap();
    let client_secret = std::env::var("CLIENT_SECRET").unwrap();
    let cookie_ssl = std::env::var("COOKIE_SSL").unwrap_or("false".to_string());
    let ping_service_url =
        std::env::var("PING_SERVICE").unwrap_or("http://localhost:8081/ping".to_string());

    let api_permission_scope = std::env::var("API_PERMISSION_SCOPE")
        .unwrap_or("api://81dd62c1-4209-4f24-bd81-99912098a77f/Ping.All".to_string());

    let use_cookie_ssl: bool = cookie_ssl.parse::<bool>().unwrap_or(false);

    let mut config = Config::new(
        redis_url,
        redis_auth_key,
        tenant_id,
        default_page,
        redirect_url,
        client_id,
        client_secret,
    );
    config.ping_url = Some(ping_service_url);
    config.api_permission_scope = Some(api_permission_scope);

    debug!("Get configuration from env complete");
    debug!("Cookie SSL : {}", use_cookie_ssl);

    match app_insights_connection_str {
        Ok(app_insights_connection_str) => {
            debug!(
                "APPLICATIONINSIGHTS_CON_STRING = {}",
                app_insights_connection_str
            );
            let exporter = opentelemetry_application_insights::new_pipeline_from_connection_string(
                app_insights_connection_str,
            )
            .unwrap()
            .with_client(reqwest::Client::new())
            .with_service_name("WebExampleAzureAD")
            .install_batch(opentelemetry::runtime::Tokio);

            let telemetry = tracing_opentelemetry::layer().with_tracer(exporter);
            let subscriber = Registry::default().with(telemetry);
            tracing::subscriber::set_global_default(subscriber)
                .expect("setting global default failed");
        }
        Err(e) => {
            error!("Application Insights connection string error {}", e);
        }
    }
    //
    // Get azure ad meta data
    //
    let url_openid_config = format!(
        r#"https://login.microsoftonline.com/{:1}/v2.0/.well-known/openid-configuration?appid={:2}"#,
        config.to_owned().tenant_id,
        config.to_owned().client_id
    );

    info!("url get azure ad configuration : {}", url_openid_config);
    let meta_azure_ad = reqwest::get(url_openid_config)
        .await
        .unwrap()
        .json::<OpenIDConfigurationV2>()
        .await;
    match meta_azure_ad {
        Ok(cnf) => {
            debug!("Meta data : {:#?}", cnf);
            config.open_id_config = Some(cnf);

            //get JWKS for verify jwt token
            let jwks_uri = config.open_id_config.clone().unwrap().jwks_uri.unwrap();
            let jwks_items = reqwest::get(jwks_uri).await.unwrap().json::<JWKS>().await;
            match jwks_items {
                Ok(jwks) => {
                    debug!("JWKS = {:#?}", jwks);
                    config.jwks = Some(jwks.clone());
                }
                Err(e) => {
                    panic!("Get jwks error : {}", e);
                }
            }
        }
        Err(e) => {
            panic!("Get meta error : {}", e);
        }
    }

    //let redis_connection = config.clone().redis_url.replace("x","");
    //let redis_connection = redis_connection.clone().replace("y",config.clone().redis_auth_key.as_str());
    let redis_connection = config.clone().redis_url.replace("redis://", "");
    debug!("Redis connection > {}", redis_connection.to_owned());

    let mut hbars = Handlebars::new();
    hbars
        .register_templates_directory(".html", "./static/")
        .unwrap();

    hbars.register_helper("access_token_validator",
                               Box::new(|h: &Helper, _r: &Handlebars, _: &Context, _rc: &mut RenderContext, out: &mut dyn Output| -> HelperResult {
                                   //let param = h.param(0).ok_or(RenderError::new("param not found"))?;
                                   //debug!("access_token_validator = {:?} , with ping_url = {:?}",param,param_ping_url);
                                   //out.write("3rd helper: ")?;
                                   //out.write(param.value().render().as_ref())?;
                                   //debug!("render param > {},",param.value().render());

                                   let param_access_token = h.param(0).ok_or(RenderError::new("param not found")).unwrap();

                                   let access_token = param_access_token.render();
                                   if access_token.is_empty() {
                                       //debug!("No Access Token");
                                       debug!("no have access token");
                                       out.write("Don't have access token")?;
                                   }else{
                                       debug!("Have Access Token");
                                       let param_ping_url = h.param(1)
                                           .ok_or(RenderError::new("param not found"))?;
                                       let out_helper = format!(r#"
                                                            <div class="card-header">Decoded JWT Access Token (for MyAPI)</div>
                                                               <div class="card-body">
                                                                     <pre id="json_access_token"> </pre>
                                                                </div>
                                                             <br/>
                                                             <input id="access_token" type="hidden" name="access_token" value="{}">
                                                             <input id="submitButton" class="btn-secondary" type="button" value="Call Ping > [{}]  with Access Token" > <br/>
                                                              <pre id="json_api_reponse"></pre>
                                                             "#,
                                                                access_token.clone(),
                                                                param_ping_url.render()
                                       );
                                       out.write(out_helper.as_str())?;

                                   }

                                   Ok(())
                               }));

    let private_key = actix_web::cookie::Key::generate();
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(config.clone()))
            .app_data(Data::new(hbars.clone()))
            .wrap(middleware::DefaultHeaders::new().add(("Dev-X-Version", "0.1")))
            .wrap(Logger::default())
            .wrap(Logger::new(
                r#"%a %t "%r" %s %b "%{Referer}i" "%{User-Agent}i" %T"#,
            ))
            .wrap_fn(|req, srv| {
                //hook all web requests
                debug!("Hi from start. You requested: {}", req.path());
                if req.path().eq("/profile") {
                    match req.method() {
                        &Method::POST | &Method::GET => {}
                        _ => {
                            //  return HttpResponse::MethodNotAllowed();
                        }
                    }
                }
                srv.call(req).map(|res| {
                    debug!("Hi from response");
                    res
                })
                ////
            })
            .wrap(middle_ware_session(
                redis_connection.as_str(),
                private_key.clone(),
                use_cookie_ssl,
            ))
            .wrap(RequestTracing::new())
            .wrap(TracingLogger::default())
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
            .service(Files::new("static", "./static").prefer_utf8(true))
    })
    // .keep_alive(KeepAlive::from(std::time::Duration::from_millis(10 * 1000)))
    .workers(10)
    .bind(("0.0.0.0", 8080))?
    .run()
    .await?;

    //opentelemetry::global::shutdown_tracer_provider();
    Ok(())
}
