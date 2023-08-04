FROM mcr.microsoft.com/devcontainers/python:1-3.11-bullseye as base


# install kaitai-struct-compiler
RUN curl -LO https://github.com/kaitai-io/kaitai_struct_compiler/releases/download/0.10/kaitai-struct-compiler_0.10_all.deb \
    && apt-get update && apt-get install -y --no-install-recommends \
    ./kaitai-struct-compiler_0.10_all.deb

# install python dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

