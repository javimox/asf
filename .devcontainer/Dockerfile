ARG NODE_IMAGE=node:22.23.1-bookworm-slim
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.31
FROM ${UV_IMAGE} AS uv
FROM ${NODE_IMAGE}

# Keep the OCI-compatible default /bin/sh. All RUN blocks below are POSIX shell,
# and pipelines are avoided so a persisted Docker-specific SHELL setting is unnecessary.

ARG TZ
ENV TZ="$TZ"

ARG CLAUDE_CODE_VERSION=2.1.216
ARG SEMGREP_VERSION=1.171.0
ARG HERMES_AGENT_COMMIT=f9eca7e15f1c2bfe5194aae5aa489af53c0a1a23
# Tirith — Hermes's pre-execution command scanner. Installed at BUILD time,
# pinned and checksum-verified, so the sandbox never needs runtime egress to
# GitHub release hosts just to bootstrap its own security tooling. Hermes's
# auto-installer is skipped because Hermes is configured with its absolute path.
ARG TIRITH_VERSION=0.4.0
ARG TIRITH_SHA256_AMD64=ec90836eef3519829f0b8371836a09c12c31fd8620d411a38b69423b19b5e468
ARG TIRITH_SHA256_ARM64=8d421d04079ad88caf660dc021bc2e8447142c2d308a4998595ba24a4d2c23c6

# System tools. netcat-openbsd provides `nc -X connect`, used to carry SSH
# over the egress proxy (ssh.github.com:443).
RUN apt-get update && apt-get install -y --no-install-recommends \
    locales \
    less \
    git \
    procps \
    util-linux \
    tar \
    zsh \
    man-db \
    unzip \
    gnupg2 \
    gh \
    iproute2 \
    iputils-ping \
    jq \
    netcat-openbsd \
    ripgrep \
    nano \
    vim \
    curl \
    ca-certificates \
    python3-pip \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen \
    && locale-gen \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8

# Semgrep — exact top-level version for repeatable builds.
RUN pip3 install "semgrep==${SEMGREP_VERSION}" --break-system-packages \
    && semgrep --version

# uv — exact image tag, copied as static binaries.
COPY --from=uv /uv /uvx /usr/local/bin/
RUN uv --version


# fzf — install a modern pinned release with native `fzf --zsh` integration.
# Debian Bookworm's package lacks the Zsh key-binding script expected by the
# Oh My Zsh plugin, so use the upstream binary and verify its checksum.
ARG FZF_VERSION=0.74.1
ARG FZF_SHA256_AMD64=df53438be5f51e151bb4044d78fda72bdfe209e3ecd2baecae48e8dea370c81b
ARG FZF_SHA256_ARM64=f22204dd1a091d43e102268d062fd53b47133c8d8581671ee5eb225b75e31183
RUN set -eu; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
      amd64) FZF_ARCH=amd64; FZF_SHA256="$FZF_SHA256_AMD64" ;; \
      arm64) FZF_ARCH=arm64; FZF_SHA256="$FZF_SHA256_ARM64" ;; \
      *) echo "ERROR: unsupported architecture for fzf: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl --fail --location --retry 5 --retry-delay 2 \
      --output /tmp/fzf.tar.gz \
      "https://github.com/junegunn/fzf/releases/download/v${FZF_VERSION}/fzf-${FZF_VERSION}-linux_${FZF_ARCH}.tar.gz"; \
    printf '%s  %s\n' "$FZF_SHA256" /tmp/fzf.tar.gz | sha256sum --check --strict -; \
    tar -xzf /tmp/fzf.tar.gz -C /usr/local/bin fzf; \
    rm /tmp/fzf.tar.gz; \
    fzf --version

# Give node user access to global npm prefix.
RUN mkdir -p /usr/local/share/npm-global && \
    mkdir -p /home/node/.hermes/bin && \
    cp /usr/local/bin/uv /home/node/.hermes/bin/uv && \
    chown -R node:node /usr/local/share /home/node/.hermes

ARG USERNAME=node

# Persist shell history across container rebuilds (populated by the named volume).
RUN mkdir /commandhistory \
    && touch /commandhistory/.bash_history \
    && chown -R "$USERNAME" /commandhistory

ENV DEVCONTAINER=true

# Workspace and agent config dirs are mounted as named volumes at runtime.
RUN mkdir -p /workspace /home/node/.claude && \
    chown -R node:node /workspace /home/node/.claude

WORKDIR /workspace

ARG GIT_DELTA_VERSION=0.18.2
RUN set -eu; \
    ARCH=$(dpkg --print-architecture); \
    curl --fail --location --retry 5 --retry-delay 2 \
        --output /tmp/git-delta.deb \
        "https://github.com/dandavison/delta/releases/download/${GIT_DELTA_VERSION}/git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb"; \
    (dpkg -i /tmp/git-delta.deb || apt-get install -fy); \
    rm /tmp/git-delta.deb; \
    delta --version

USER node

ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin
ENV SHELL=/bin/zsh
ENV EDITOR=nano
ENV VISUAL=nano
# Keep the completion cache stable across Podman/libkrun hostnames.
ENV ZSH_COMPDUMP=/home/node/.zcompdump

ARG ZSH_IN_DOCKER_VERSION=1.2.0
RUN set -eu; \
    curl --fail --location --retry 5 --retry-delay 2 \
        --output /tmp/zsh-in-docker.sh \
        "https://github.com/deluan/zsh-in-docker/releases/download/v${ZSH_IN_DOCKER_VERSION}/zsh-in-docker.sh"; \
    sh /tmp/zsh-in-docker.sh \
        -p git \
        -p fzf \
        -a "export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
        -x; \
    rm /tmp/zsh-in-docker.sh

# Pre-generate the completion dump without starting an interactive shell.
# This avoids ZLE warnings during image builds while keeping the first real
# terminal prompt fast.
RUN zsh -f -c ' \
    fpath=("$HOME/.oh-my-zsh/functions" "$HOME/.oh-my-zsh/completions" \
      "$HOME/.oh-my-zsh/plugins/git" "$HOME/.oh-my-zsh/plugins/fzf" $fpath); \
    autoload -Uz compinit; \
    compinit -d "$ZSH_COMPDUMP" \
'

COPY --chown=node:node \
    agents/hermes/patches/gpt-5.6-reasoning-none.patch \
    /tmp/hermes-gpt-5.6-reasoning-none.patch
COPY --chown=node:node \
    agents/hermes/patches/tirith-fail-closed.patch \
    /tmp/hermes-tirith-fail-closed.patch

# ── Agent install (only the selected agent) ───────────────────────────────────
ARG AGENT=claude
RUN set -eu; \
    case "$AGENT" in \
      claude) \
        echo ">>> Installing Claude Code ${CLAUDE_CODE_VERSION}"; \
        npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"; \
        claude --version ;; \
      hermes) \
        echo ">>> Installing Hermes agent at ${HERMES_AGENT_COMMIT}"; \
        curl --fail --location --retry 5 --retry-delay 2 \
          --output /tmp/hermes-install.sh \
          "https://raw.githubusercontent.com/NousResearch/hermes-agent/${HERMES_AGENT_COMMIT}/scripts/install.sh"; \
        bash /tmp/hermes-install.sh \
          --commit "$HERMES_AGENT_COMMIT" \
          --skip-setup \
          --skip-browser \
          --non-interactive; \
        rm /tmp/hermes-install.sh; \
        HERMES_REPO=/home/node/.hermes/hermes-agent; \
        echo ">>> Applying ASF Tirith fail-closed compatibility patch"; \
        git -C "$HERMES_REPO" apply --check /tmp/hermes-tirith-fail-closed.patch; \
        git -C "$HERMES_REPO" apply /tmp/hermes-tirith-fail-closed.patch; \
        echo ">>> Verifying the Hermes CLI installation (normally under 2 minutes)"; \
        test -x /home/node/.local/bin/hermes; \
        if ! timeout 120 /home/node/.local/bin/hermes --help >/dev/null; then \
          echo "ERROR: Hermes CLI verification failed or exceeded 120 seconds" >&2; \
          exit 1; \
        fi; \
        echo ">>> Hermes CLI verified"; \
        echo ">>> Podman is now saving the Hermes image layer; no output may appear for a few minutes" ;; \
      generic) \
        echo ">>> Generic runtime: no agent product installed"; \
        echo ">>> Python, pip, and uv are already present in the base image"; \
        python3 --version; uv --version ;; \
      *) \
        echo "ERROR: unknown AGENT='$AGENT'" >&2; \
        echo "  Known adapters: claude, hermes, generic" >&2; \
        echo "  Set 'adapter: generic' in agents/$AGENT/runtime.yml" >&2; \
        exit 1 ;; \
    esac

ENV PATH="/home/node/.local/bin:/home/node/.hermes/bin:${PATH}"
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

# ── Hermes-only Tirith scanner (mandatory, pinned, checksum-verified) ────────
# Installed to /usr/local/bin, outside the ~/.hermes named volume. Hermes
# selects this absolute path so persistent user state cannot shadow it. With
# tirith_fail_open:false a missing scanner blocks every terminal command, so a
# failed download or checksum mismatch must FAIL THE BUILD, not degrade.
USER root
RUN set -eu; \
    if [ "$AGENT" = "hermes" ]; then \
        echo ">>> Installing Tirith ${TIRITH_VERSION}"; \
        ARCH=$(dpkg --print-architecture); \
        case "$ARCH" in \
          amd64) TIRITH_TARGET=x86_64-unknown-linux-gnu; TIRITH_SHA256="$TIRITH_SHA256_AMD64" ;; \
          arm64) TIRITH_TARGET=aarch64-unknown-linux-gnu; TIRITH_SHA256="$TIRITH_SHA256_ARM64" ;; \
          *) echo "ERROR: unsupported architecture for tirith: $ARCH" >&2; exit 1 ;; \
        esac; \
        curl --fail --location --retry 5 --retry-delay 2 \
          --output /tmp/tirith.tar.gz \
          "https://github.com/sheeki03/tirith/releases/download/v${TIRITH_VERSION}/tirith-${TIRITH_TARGET}.tar.gz"; \
        printf '%s  %s\n' "$TIRITH_SHA256" /tmp/tirith.tar.gz | sha256sum --check --strict -; \
        tar -xzf /tmp/tirith.tar.gz -C /usr/local/bin tirith; \
        rm /tmp/tirith.tar.gz; \
        chmod 0755 /usr/local/bin/tirith; \
        tirith --version; \
    fi
USER node

# ── Hermes-only optional media + browser provisioning ────────────────────────
# Hermes itself is mandatory above. Browser/TTS extras remain best-effort and
# emit explicit warnings because they are not required for terminal operation.
USER root
RUN set -u; \
    if [ "$AGENT" = "hermes" ]; then \
        echo ">>> Provisioning optional Hermes media + browser dependencies"; \
        if apt-get update && apt-get install -y --no-install-recommends ffmpeg; then \
            echo ">>> ffmpeg installed"; \
        else \
            echo "WARNING: optional ffmpeg install failed" >&2; \
        fi; \
        mkdir -p "$PLAYWRIGHT_BROWSERS_PATH"; \
        HERMES_REPO=/home/node/.hermes/hermes-agent; \
        PW=$(find "$HERMES_REPO" -maxdepth 4 -path '*/node_modules/.bin/playwright' -type f -print -quit 2>/dev/null); \
        if [ -n "$PW" ] && [ -x "$PW" ]; then \
            "$PW" install-deps chromium || echo "WARNING: optional Playwright dependencies failed" >&2; \
            "$PW" install chromium || echo "WARNING: optional Chromium download failed" >&2; \
        else \
            echo "WARNING: Playwright not found; browser tools are unavailable" >&2; \
        fi; \
        chown -R node:node "$PLAYWRIGHT_BROWSERS_PATH"; \
        apt-get clean; \
        rm -rf /var/lib/apt/lists/*; \
    fi
USER node

# No privileged helper and no sudo rule: egress is enforced OUTSIDE the
# container by network topology (see lib/network.sh, lib/proxy.sh).
