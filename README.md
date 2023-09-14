# webexampleopenidc002
Test Simple Web Application Integration with Azure AD, Uses Rust + Actix Web Framework

Example Run

```
REDIS_URL=redis://localhost:6379 \
REDIS_AUTH_KEY=[redis pass key] \
TENANT_ID=[Azure Tenant Id] \
DEFAULT_PAGE=http://localhost:8080 \
REDIRECT_URL=http://localhost:8080/callback \
CLIENT_ID=[Azure Client Id] \
CLIENT_SECRET=[Azure Client Secret] \
API_PERMISSION_SCOPE=api://[azure api id]/[scope] \
COOKIE_SSL=false \
PING_SERVICE=[example api to call -> http://localhost:8081/ping (this api must check access token)] \
RUST_LOG=debug cargo run
```

