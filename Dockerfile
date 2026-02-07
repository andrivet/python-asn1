# Use 20.04 to avoid OpenSSL-related issues with Python 2.7, 3.5 and 3.6
FROM ubuntu:20.04
LABEL authors="Sebastien Andrivet"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl git \
      build-essential make \
      zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
      libffi-dev liblzma-dev tk-dev \
      libssl-dev \
      xz-utils \
      python3 python3-venv python3-pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# -------------------------
# pyenv (for Python 2.7 / 3.5 / 3.6 / 3.7)
# -------------------------
ENV PYENV_ROOT=/opt/pyenv
ENV PATH="${PYENV_ROOT}/bin:${PYENV_ROOT}/shims:${PATH}"

RUN git clone https://github.com/pyenv/pyenv.git "${PYENV_ROOT}"

RUN /bin/bash -lc '\
  set -euxo pipefail; \
  pyenv install 2.7.18; \
  pyenv install 3.5.10; \
  pyenv install 3.6.15; \
  pyenv install 3.7.17; \
  ln -sf "${PYENV_ROOT}/versions/2.7.18/bin/python" /usr/local/bin/python2.7; \
  ln -sf "${PYENV_ROOT}/versions/3.5.10/bin/python" /usr/local/bin/python3.5; \
  ln -sf "${PYENV_ROOT}/versions/3.6.15/bin/python" /usr/local/bin/python3.6; \
  ln -sf "${PYENV_ROOT}/versions/3.7.17/bin/python" /usr/local/bin/python3.7; \
  ln -sf "${PYENV_ROOT}/versions/2.7.18/bin/pip" /usr/local/bin/pip2.7 || true; \
  ln -sf "${PYENV_ROOT}/versions/3.5.10/bin/pip" /usr/local/bin/pip3.5 || true; \
  ln -sf "${PYENV_ROOT}/versions/3.6.15/bin/pip" /usr/local/bin/pip3.6 || true; \
  ln -sf "${PYENV_ROOT}/versions/3.7.17/bin/pip" /usr/local/bin/pip3.7 || true; \
'

# -------------------------
# uv (for Python 3.8 and later)
# -------------------------
COPY --from=docker.io/astral/uv:latest /uv /uvx /usr/local/bin/

ENV UV_PYTHON_INSTALL_DIR=/opt/uv-python

RUN /bin/bash -lc '\
  set -euxo pipefail; \
  uv python install 3.8 3.9 3.10 3.11 3.12 3.13 3.14; \
  for v in 3.8 3.9 3.10 3.11 3.12 3.13 3.14; do \
    p="$(uv python find "$v")"; \
    ln -sf "$p" "/usr/local/bin/python${v}"; \
  done; \
'

# -------------------------
# tox installs
#   - tox<4: legacy (py27/py35/py36)
#   - tox>=4: modern  (py37+)
# -------------------------
RUN python3 -m venv /opt/tox3 && \
    /opt/tox3/bin/pip install -U pip && \
    /opt/tox3/bin/pip install "tox<4" "virtualenv<20.22" && \
    python3 -m venv /opt/tox4 && \
    /opt/tox4/bin/pip install -U pip && \
    /opt/tox4/bin/pip install "tox>=4"

# Wrapper: run legacy envs with tox3, modern envs with tox4
RUN cat >/usr/local/bin/run-tox <<'SH'
#!/bin/sh
set -eu
/opt/tox3/bin/tox -e py27,py35,py36,py37 "$@"
/opt/tox4/bin/tox -e py38,py39,py310,py311,py312,py313,py314 "$@"
SH
RUN chmod +x /usr/local/bin/run-tox

# Non-root user
RUN useradd --create-home user && \
    mkdir -p /home/user/project && \
    chown -R user:user /home/user/project

USER user
WORKDIR /home/user/project
COPY --chown=user . .

# Default: run the split tox wrapper (NOT plain "tox")
CMD ["run-tox"]
