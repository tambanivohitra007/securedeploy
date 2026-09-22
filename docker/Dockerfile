# SecureDeploy Docker image — all tools pre-installed
# Build: docker build -t securedeploy:latest -f docker/Dockerfile .
# Run:   docker run --rm -v $(pwd):/workspace securedeploy:latest test

ARG TRIVY_VERSION=0.55.0
ARG NUCLEI_VERSION=3.3.0
ARG SEMGREP_VERSION=1.85.0

# ── Stage 1: Download and verify tool binaries ───────────────────────────────
FROM ubuntu:24.04 AS tool-downloader

ARG TRIVY_VERSION
ARG NUCLEI_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# Trivy
RUN curl -sSfL \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    -o trivy.tar.gz \
    && tar -xzf trivy.tar.gz trivy \
    && chmod +x trivy \
    && rm trivy.tar.gz

# Nuclei
RUN curl -sSfL \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -o nuclei.zip \
    && unzip -q nuclei.zip nuclei \
    && chmod +x nuclei \
    && rm nuclei.zip

# ── Stage 2: Python + Semgrep + framework ────────────────────────────────────
FROM python:3.12-slim AS final

ARG SEMGREP_VERSION

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy tool binaries from downloader stage
COPY --from=tool-downloader /tools/trivy /usr/local/bin/trivy
COPY --from=tool-downloader /tools/nuclei /usr/local/bin/nuclei

# Install Semgrep (Python package — engine is LGPL-2.1)
RUN pip install --no-cache-dir semgrep==${SEMGREP_VERSION}

# Install SecureDeploy
WORKDIR /app
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e .

# Update Nuclei templates on build
RUN nuclei -update-templates -silent || true

WORKDIR /workspace

ENTRYPOINT ["securedeploy"]
CMD ["--help"]

# Build-time labels
LABEL org.opencontainers.image.title="SecureDeploy"
LABEL org.opencontainers.image.description="Pre-deployment security testing framework"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/securedeploy/securedeploy"
