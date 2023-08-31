################
##### Builder
FROM rust:1.71.1-alpine3.17 as chef

RUN apk add --no-cache musl-dev gcc openssl-dev
RUN cargo install cargo-chef
WORKDIR app

FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .

RUN cargo build --release

################
##### Runtime
FROM alpine:3.17 AS runtime

RUN apk add openssl-dev
RUN apk --no-cache add ca-certificates \
    && rm -rf /var/cache/apk/*

RUN openssl s_client -connect graph.microsoft.com:443 -showcerts </dev/null 2>/dev/null | sed -e '/-----BEGIN/,/-----END/!d' | tee "/etc/ssl/certs/ca-certificates.crt" >/dev/null && \
update-ca-certificates

RUN openssl s_client -connect login.microsoftonline.com:443 -showcerts </dev/null 2>/dev/null | sed -e '/-----BEGIN/,/-----END/!d' | tee "/etc/ssl/certs/ca-certificates.crt" >/dev/null && \
update-ca-certificates

RUN addgroup -S myuser && adduser -S myuser -G myuser

RUN mkdir app_example
WORKDIR /app
COPY --from=builder /app/target/release/webexampleopenidc002 /app_example
COPY static/ /app_example/static/
RUN ls -la /app_example/static/*

WORKDIR /app_example
EXPOSE 8080
USER myuser
CMD ["./webexampleopenidc002"]

