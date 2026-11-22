# isomdl-uniffi for mdoc support. ISOMDL_VERSION is a tag, branch or commit of
# ISOMDL_REPO.
#
# The default is the timbl-ont fork's feat/prepared-mdoc-new-from-cbor branch,
# pinned by commit: Indicio's v0.2.0-indicio.2 plus PreparedMdoc.new_from_cbor.
# The fork publishes no wheels, so every architecture builds it from source.
# With Indicio's repository and a release tag, amd64 installs the release wheel
# instead and only arm64 builds from source.
ARG ISOMDL_REPO=https://github.com/timbl-ont/isomdl-uniffi
ARG ISOMDL_VERSION=5304a2ea1abc3e62585cce764390b58738942bee

FROM python:3.13-slim-bookworm AS base
WORKDIR /usr/src/app

# Install and configure poetry
USER root

# Install and configure poetry
WORKDIR /usr/src/app
ENV POETRY_VERSION=2.1.2
ENV POETRY_HOME=/opt/poetry
RUN apt-get update && apt-get install -y curl jq && apt-get clean
RUN curl -sSL https://install.python-poetry.org | python -

ENV PATH="/opt/poetry/bin:$PATH"
RUN poetry config virtualenvs.in-project true

# Setup project
RUN mkdir oid4vc && touch oid4vc/__init__.py
RUN mkdir jwt_vc_json && touch jwt_vc_json/__init__.py
RUN mkdir sd_jwt_vc && touch sd_jwt_vc/__init__.py
RUN mkdir mso_mdoc && touch mso_mdoc/__init__.py
RUN mkdir status_list && touch status_list/__init__.py
RUN mkdir mso_mdoc/isomdl
RUN mkdir -p keycloak/oid4vc_keycloak && touch keycloak/oid4vc_keycloak/__init__.py
COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --without dev --all-extras

ARG TARGETARCH
ARG ISOMDL_REPO
ARG ISOMDL_VERSION
# Since v0.2 the repository's .cargo/config.toml links Linux targets with
# `zig cc` (mise/scripts/*-cc.sh) for Indicio's cross-compiled Kotlin builds.
# zig cc rejects the -Wl,--fix-cortex-a53-843419 that rustc passes on aarch64,
# so link with the system compiler, as Indicio's own manylinux wheel build does.
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=cc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc
RUN mkdir -p isomdl-uniffi/python/isomdl_uniffi && \
    if [ "$TARGETARCH" = "arm64" ] || [ "$ISOMDL_REPO" != "https://github.com/Indicio-tech/isomdl-uniffi" ]; then \
        apt-get update && apt-get install -y git build-essential && apt-get clean && \
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
        rm -rf isomdl-uniffi && git init -q isomdl-uniffi && cd isomdl-uniffi && \
        git fetch -q --depth 1 "$ISOMDL_REPO.git" "$ISOMDL_VERSION" && git checkout -q FETCH_HEAD && \
        cd python && PATH="/root/.cargo/bin:$PATH" python build.py; \
    fi

USER $user

FROM python:3.13-bookworm

ARG TARGETARCH
ARG ISOMDL_REPO
ARG ISOMDL_VERSION

WORKDIR /usr/src/app
COPY --from=base /usr/src/app/.venv /usr/src/app/.venv
ENV PATH="/usr/src/app/.venv/bin:$PATH"
RUN apt-get update && apt-get install -y curl jq && apt-get clean
COPY jwt_vc_json/ jwt_vc_json/
COPY mso_mdoc/ mso_mdoc/
COPY sd_jwt_vc/ sd_jwt_vc/
COPY oid4vc/ oid4vc/
COPY keycloak/oid4vc_keycloak/ keycloak/oid4vc_keycloak/
ADD https://github.com/openwallet-foundation/acapy-plugins.git#main:status_list/status_list/ status_list/
# X.509 certificates for wallet keys: mso_mdoc's document signer certificates.
ADD https://github.com/openwallet-foundation/acapy-plugins.git#main:x509_certs/x509_certs/ x509_certs/
COPY docker/*.yml ./


# isomdl-uniffi: the bindings built from source in the base stage, or, for an
# Indicio release on amd64, the release wheel (the base stage's directory is
# then empty).
COPY --from=base /usr/src/app/isomdl-uniffi/python/isomdl_uniffi /usr/src/app/mso_mdoc/isomdl
ENV PYTHONPATH="/usr/src/app/mso_mdoc/isomdl:$PYTHONPATH"
RUN if [ "$TARGETARCH" != "amd64" ] && [ "$TARGETARCH" != "arm64" ]; then \
        echo "Unsupported architecture: $TARGETARCH"; \
        exit 1; \
    elif [ "$TARGETARCH" = "amd64" ] && [ "$ISOMDL_REPO" = "https://github.com/Indicio-tech/isomdl-uniffi" ]; then \
        wheel_version="${ISOMDL_VERSION#v}"; wheel_version="${wheel_version%%-*}"; \
        pip install --no-cache-dir "${ISOMDL_REPO}/releases/download/${ISOMDL_VERSION}/isomdl_uniffi-${wheel_version}-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"; \
    fi

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
