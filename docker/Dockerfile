# euvd-watch container image (plans/implementation_plan.md Step 5.2).
#
# Build from the repository root (the build context must contain pyproject.toml and src/):
#   docker build -f docker/Dockerfile -t euvd-watch .
# Run:
#   docker run --rm -v "$PWD:/work:ro" euvd-watch match /work/sbom.cdx.json
#
# Multi-stage: the wheel is built in a throwaway stage so the final image carries no
# build tooling; runs as a non-root user; size budget < 200 MB (enforced in CI).

FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml LICENSE ./
COPY readme/ readme/
COPY src/ src/
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim

ARG SOURCE_URL="https://github.com/<org>/euvd-watch"
LABEL org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.description="EUVD-native supply-chain vulnerability watch + CRA reporting toolkit" \
      org.opencontainers.image.licenses="EUPL-1.2"

RUN useradd --create-home --uid 1000 euvd
COPY --from=build /dist/*.whl /tmp/dist/
RUN pip install --no-cache-dir /tmp/dist/*.whl && rm -rf /tmp/dist

USER euvd
WORKDIR /work
# Cache and durable state live in the euvd user's home; mount volumes over these paths
# to persist them across runs (see docs/integrations.md).
ENTRYPOINT ["euvd-watch"]
CMD ["--help"]
