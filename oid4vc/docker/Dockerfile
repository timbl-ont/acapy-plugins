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
COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --without dev --all-extras

# ---------------------------------------------------------------------------
# isomdl-uniffi bindings
#
# Indicio publish a prebuilt wheel for linux/x86_64 only (the rest of the
# release is macOS and Windows), so x86_64 installs that wheel directly.  Any
# other architecture -- arm64 in particular -- has no wheel available and has to
# compile the bindings from source.
#
# That build needs Rust and also zig: isomdl-uniffi's cargo config uses zig as
# its C linker, pinned to 0.16 by the project's mise.toml.
#
# Both paths install into the project virtualenv, which the runtime stage
# already copies, so neither the Rust nor the zig toolchain reaches the final
# image.  The architecture is read from uname so the build needs no build args.
# ---------------------------------------------------------------------------
ARG ISOMDL_VERSION=v0.1.0-indicio.1
ARG ZIG_VERSION=0.16.0
RUN set -eux; \
    ARCH="$(uname -m)"; \
    if [ "$ARCH" = "x86_64" ]; then \
        .venv/bin/pip install --no-cache-dir \
            "https://github.com/Indicio-tech/isomdl-uniffi/releases/download/${ISOMDL_VERSION}/isomdl_uniffi-0.1.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"; \
    else \
        case "$ARCH" in \
            aarch64|arm64) \
                ZIG_ARCH=aarch64-linux; \
                ZIG_SHA256=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17 ;; \
            *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
        esac; \
        apt-get update; \
        apt-get install -y git build-essential xz-utils; \
        apt-get clean; \
        curl -sSL -o /tmp/zig.tar.xz \
            "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_ARCH}-${ZIG_VERSION}.tar.xz"; \
        echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c -; \
        tar -xJf /tmp/zig.tar.xz -C /usr/local; \
        ln -s "/usr/local/zig-${ZIG_ARCH}-${ZIG_VERSION}/zig" /usr/local/bin/zig; \
        rm /tmp/zig.tar.xz; \
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
        export PATH="/root/.cargo/bin:/usr/local/bin:${PATH}"; \
        git clone --depth 1 --branch "${ISOMDL_VERSION}" \
            https://github.com/Indicio-tech/isomdl-uniffi.git /tmp/isomdl-uniffi; \
        cd /tmp/isomdl-uniffi/python; \
        chmod +x precommit/*.sh; \
        python build.py; \
        /usr/src/app/.venv/bin/pip install --no-cache-dir .; \
        cd /; \
        rm -rf /tmp/isomdl-uniffi /root/.cargo /root/.rustup; \
    fi; \
    /usr/src/app/.venv/bin/python -c "import isomdl_uniffi; print('isomdl_uniffi OK')"

USER $user

FROM python:3.13-bookworm

WORKDIR /usr/src/app
COPY --from=base /usr/src/app/.venv /usr/src/app/.venv
ENV PATH="/usr/src/app/.venv/bin:$PATH"
RUN apt-get update && apt-get install -y curl jq && apt-get clean
COPY jwt_vc_json/ jwt_vc_json/
COPY mso_mdoc/ mso_mdoc/
COPY sd_jwt_vc/ sd_jwt_vc/
COPY oid4vc/ oid4vc/
ADD https://github.com/openwallet-foundation/acapy-plugins.git#main:status_list/status_list/ status_list/
COPY docker/*.yml ./

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
