# =============================================================================
# VulnPredict Docker Image
# Multi-stage build for a slim, production-ready container
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build dependencies
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

# Install build essentials for compiling Python packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only dependency files first for better layer caching
COPY pyproject.toml ./
COPY src/ src/

# Build the wheel
RUN pip install --no-cache-dir build && \
    python -m build --wheel --outdir /build/dist

# Install the wheel and all dependencies into a prefix
RUN pip install --no-cache-dir --prefix=/install /build/dist/*.whl

# ---------------------------------------------------------------------------
# Stage 2: Production image
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS production

LABEL org.opencontainers.image.title="VulnPredict"
LABEL org.opencontainers.image.description="Predictive Vulnerability Intelligence Tool — static analysis with ML-powered risk scoring"
LABEL org.opencontainers.image.source="https://github.com/thehhugg/vulnpredict"
LABEL org.opencontainers.image.licenses="MIT"

# Install Node.js (LTS) for JavaScript analysis and git for churn features
# Uses GPG key verification instead of curl|bash for security
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | \
        gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g esprima eslint && \
    apt-get purge -y --auto-remove ca-certificates curl gnupg && \
    rm -rf /var/lib/apt/lists/* /tmp/* /root/.npm

# Copy Python installation from builder
COPY --from=builder /install /usr/local

# Create non-root user for security
RUN groupadd -r vulnpredict && \
    useradd -r -g vulnpredict -d /home/vulnpredict -s /sbin/nologin vulnpredict && \
    mkdir -p /home/vulnpredict/.cache/vulnpredict && \
    chown -R vulnpredict:vulnpredict /home/vulnpredict

# Set cache directory for OSV.dev and model data
ENV VULNPREDICT_CACHE_DIR=/home/vulnpredict/.cache/vulnpredict
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER vulnpredict
WORKDIR /code

# Health check: verify the CLI is functional
HEALTHCHECK --interval=30s --timeout=5s --retries=1 \
    CMD vulnpredict --help > /dev/null 2>&1 || exit 1

ENTRYPOINT ["vulnpredict"]
CMD ["--help"]
