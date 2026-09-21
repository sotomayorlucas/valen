# Reproducible artifact for VALEN.
#
# Build:  docker build -t valen .
# Run:    docker run --rm -it valen            # tests + toy demo
#         docker run --rm -it valen scripts/reproduce.sh --fetch-owasp
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential curl git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Rust toolchain (for the numeric core).
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# Tectonic (self-contained LaTeX) for the paper/slides.
RUN curl -sL https://github.com/tectonic-typesetting/tectonic/releases/download/tectonic%400.17.0/tectonic-0.17.0-x86_64-unknown-linux-musl.tar.gz \
      | tar xz -C /usr/local/bin tectonic

WORKDIR /valen
COPY requirements.txt pyproject.toml ./
RUN python -m venv .venv && .venv/bin/pip install -q -r requirements.txt

COPY . .
RUN cargo build --release --manifest-path core/Cargo.toml

CMD ["bash", "-lc", ".venv/bin/python -m pytest tests/ -q && .venv/bin/python scripts/demo.py"]
