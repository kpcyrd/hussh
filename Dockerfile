FROM rust:1-alpine3.24
ENV RUSTFLAGS="-C strip=debuginfo"
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/hussh /

FROM alpine:3.24
RUN apk add libcap-setcap
COPY --from=0 /hussh /
COPY contrib/hussh.conf /etc/
RUN setcap cap_net_bind_service=+ep /hussh
USER nobody
VOLUME ["/data"]
ENV HUSSH_DATA_DIR=/data
ENTRYPOINT ["/hussh"]
CMD ["-c", "/etc/hussh.conf"]
