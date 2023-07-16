FROM rust:1.71.0-alpine3.18

RUN apk add alpine-sdk

WORKDIR /opt/app
COPY . . 
RUN cargo build --release
CMD cargo run --release
