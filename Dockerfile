FROM ubuntu:22.04
LABEL authors="Sebastien Andrivet"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt install software-properties-common -y && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y --no-install-recommends git curl && \
    apt-get install -y --no-install-recommends \
      python2.7 \
      python3.4 \
      python3.5 \
      # python3.6 python3.6-distutils \
      python3.7 python3.7-distutils \
      python3.8 python3.8-distutils \
      # python3.9 \
      python3.10 \
      python3.11 \
      python3.12 \
      python3.13 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12
RUN pip3 install --upgrade pip setuptools wheel tox

RUN useradd --create-home user
RUN mkdir /home/user/project && chown user:user /home/user/project

USER user
WORKDIR /home/user/project
COPY --chown=user . .

CMD ["tox"]
