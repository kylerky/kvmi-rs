FROM rust:latest
RUN set -eux; \
    apt update; \
    apt install -y --no-install-recommends clang llvm-dev; \
    rustup component add rustfmt clippy;