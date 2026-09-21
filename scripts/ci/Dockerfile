ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

COPY scripts/ci/install-deps.sh /tmp/install-deps.sh
RUN sh /tmp/install-deps.sh
ENV CARGO_HOME=/opt/fp-cargo RUSTUP_HOME=/opt/fp-rustup
ENV PATH=/opt/fp-cargo/bin:/opt/fp-venv/bin:$PATH
ENV CARGO_BUILD_JOBS=2
WORKDIR /work
COPY rust-toolchain.toml ./
RUN curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs -o /tmp/rustup.sh \
    && sh /tmp/rustup.sh -y --profile minimal --default-toolchain none \
    && rustup show active-toolchain
COPY scripts/requirements-test.txt /tmp/requirements-test.txt
RUN python3 -m venv /opt/fp-venv && pip install --no-cache-dir -r /tmp/requirements-test.txt
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY examples ./examples
COPY scripts ./scripts
# Alpine binds to its dynamically linked libclang while Rust defaults to static
# musl linkage. Build this container's binaries dynamically so bindgen can load it.
RUN if [ -f /etc/alpine-release ]; then \
      mkdir -p .cargo && printf '[build]\nrustflags = ["-C", "target-feature=-crt-static"]\n' > .cargo/config.toml; \
    fi \
    && cargo build --locked --bin fingerprint-bridge --example language-client \
    && cargo test --locked --no-run \
    && mkdir -p target/matrix-clients \
    && go build -o target/matrix-clients/go-client scripts/clients/go_client.go \
    && javac -d target/matrix-clients scripts/clients/JavaClient.java
CMD ["python3", "scripts/matrix_lab.py", "--output", "/evidence"]
