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
COPY README.md ./
COPY src/ src/
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim

ARG SOURCE_URL="https://github.com/<org>/euvd-watch"
LABEL org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.description="EUVD-native supply-chain vulnerability watch + CRA reporting toolkit" \
      org.opencontainers.image.licenses="EUPL-1.2"

RUN useradd --create-home --uid 1000 euvd
COPY --from=build /dist/*.whl /tmp/dist/
# Install WITH the [web] extra: the image is the deployment vehicle for the self-hostable
# dashboard (docs/deploy.md), so `euvd-watch web serve` must work out of the box. The
# `[web]` extra keeps the *pip* install lean for CLI-only users; the all-in-one image
# deliberately includes it. Extra applied to the local wheel (not `euvd-watch[web]` from
# an index) so the image always ships the code that was just built.
RUN wheel="$(ls /tmp/dist/*.whl)" && pip install --no-cache-dir "${wheel}[web]" && rm -rf /tmp/dist

# Pre-create the cache and durable-state dirs owned by euvd. A Docker *named volume*
# mounted over an existing image directory inherits that directory's ownership, so this
# is what lets the non-root euvd user write to a persisted `-v euvd-state:...` volume
# (docs/deploy.md, docs/integrations.md). Without it the volume mounts root-owned and
# every write fails with EACCES.
RUN mkdir -p /home/euvd/.local/share/euvd-watch /home/euvd/.cache/euvd-watch \
    && chown -R euvd:euvd /home/euvd/.local /home/euvd/.cache

USER euvd
WORKDIR /work
# Cache and durable state live in the euvd user's home; mount volumes over these paths
# to persist them across runs (see docs/integrations.md).
ENTRYPOINT ["euvd-watch"]
CMD ["--help"]
