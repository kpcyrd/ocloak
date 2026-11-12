FROM rust:1-alpine3.24
ENV RUSTFLAGS="-C strip=debuginfo"
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/ocloak /

FROM alpine:3.24
RUN apk add libcap-setcap
COPY --from=0 /ocloak /
COPY contrib/ocloak.conf /etc/
RUN setcap cap_net_bind_service=+ep /ocloak
USER nobody
ENTRYPOINT ["/ocloak"]
CMD ["daemon", "-c", "/etc/ocloak.conf"]
