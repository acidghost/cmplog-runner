FROM ubuntu:20.04
RUN apt-get update \
 && apt-get install -y \
        build-essential \
        clang-12 \
        curl \
        git \
        llvm-12
WORKDIR /work
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git \
 && cd AFLplusplus \
 && LLVM_CONFIG=llvm-config-12 make source-only \
 && make install
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable
