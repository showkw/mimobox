# syntax=docker/dockerfile:1

FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:/usr/local/bin:$PATH \
    VM_ASSETS_DIR=/opt/mimobox-assets \
    ALPINE_VERSION=3.20 \
    ALPINE_APK_TOOLS_VERSION=2.14.4-r0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        curl \
        ca-certificates \
        gcc \
        cpio \
        gzip \
        python3 \
        bison \
        flex \
        bc \
        perl \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# scripts/build-rootfs.sh 在本地构建路径中优先调用 apk 安装 guest 运行时。
# Docker build 阶段没有 Docker daemon，因此这里安装 Alpine 的静态 apk。
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
        amd64) alpine_arch="x86_64" ;; \
        *) echo "不支持的构建架构: ${arch}" >&2; exit 1 ;; \
    esac; \
    apk_pkg="apk-tools-static-${ALPINE_APK_TOOLS_VERSION}.apk"; \
    curl -fSL "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/main/${alpine_arch}/${apk_pkg}" -o "/tmp/${apk_pkg}"; \
    mkdir -p /tmp/apk-tools /etc/apk/keys; \
    tar -xzf "/tmp/${apk_pkg}" -C /tmp/apk-tools; \
    install -m 0755 /tmp/apk-tools/sbin/apk.static /usr/local/bin/apk; \
    printf 'https://dl-cdn.alpinelinux.org/alpine/v%s/main\nhttps://dl-cdn.alpinelinux.org/alpine/v%s/community\n' "${ALPINE_VERSION}" "${ALPINE_VERSION}" > /etc/apk/repositories; \
    curl -fSL "https://alpinelinux.org/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub" -o /etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub; \
    curl -fSL "https://alpinelinux.org/keys/alpine-devel@lists.alpinelinux.org-61666e3f.rsa.pub" -o /etc/apk/keys/alpine-devel@lists.alpinelinux.org-61666e3f.rsa.pub; \
    curl -fSL "https://alpinelinux.org/keys/alpine-devel@lists.alpinelinux.org-616a9724.rsa.pub" -o /etc/apk/keys/alpine-devel@lists.alpinelinux.org-616a9724.rsa.pub; \
    rm -rf /tmp/apk-tools "/tmp/${apk_pkg}"

RUN curl -fsSL https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable \
    && rustc --version \
    && cargo --version

WORKDIR /workspace
COPY . .

RUN cargo build --release -p mimobox-cli --features mimobox-cli/full,mimobox-sdk/vm,mimobox-sdk/wasm

RUN mkdir -p "${VM_ASSETS_DIR}" \
    && OUTPUT="${VM_ASSETS_DIR}/rootfs.cpio.gz" scripts/build-rootfs.sh \
    && OUTPUT="${VM_ASSETS_DIR}/vmlinux" scripts/build-kernel.sh \
    && test -x target/release/mimobox-cli \
    && test -s "${VM_ASSETS_DIR}/rootfs.cpio.gz" \
    && test -s "${VM_ASSETS_DIR}/vmlinux"

FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    VM_ASSETS_DIR=/opt/mimobox-assets

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/mimobox-cli /usr/local/bin/mimobox
COPY --from=builder /opt/mimobox-assets/ /opt/mimobox-assets/
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh \
    && chmod 0755 /usr/local/bin/mimobox

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["shell", "--backend", "auto"]
