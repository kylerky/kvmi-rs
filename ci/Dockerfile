# VERSION 1.0.1

FROM rust:latest
RUN set -eux; \
    apt update; \
    apt install -y --no-install-recommends clang llvm-dev capnproto; \
    rustup component add rustfmt clippy;