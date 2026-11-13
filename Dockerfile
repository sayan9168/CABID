# CABID container image.
#
# Deliberately small and unprivileged: CABID analyzes logs it is given, it does
# not need the host filesystem, the socket directory, or root.
#
#   docker build -t cabid:0.7.0 .
#   docker run --rm -v "$PWD/datasets:/data:ro" cabid:0.7.0 \
#     analyze /data/synthetic/example.jsonl --format md
#
# Mount event logs read-only. If you mount a host log directory writable you have
# removed the only thing keeping a parsing bug away from your evidence.
FROM python:3.12-slim AS build

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY cabid ./cabid
RUN python -m pip install --upgrade pip build \
 && python -m build --wheel --outdir /dist

FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=build /dist/*.whl /tmp/
RUN python -m pip install --upgrade pip \
 && python -m pip install /tmp/*.whl \
 && rm -f /tmp/*.whl

# Unprivileged runtime user. A numeric uid keeps Kubernetes runAsNonRoot happy.
RUN useradd --create-home --uid 10001 cabid
USER 10001
WORKDIR /home/cabid

# The console script is the entrypoint; `python -m cabid` is equivalent.
ENTRYPOINT ["cabid"]
CMD ["--help"]

LABEL org.opencontainers.image.title="CABID" \
      org.opencontainers.image.description="Telemetry-aware causal behavioral analysis for Linux security research" \
      org.opencontainers.image.source="https://github.com/sayan9168/CABID" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.documentation="https://github.com/sayan9168/CABID/tree/main/docs"
