FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config git \
    libsodium-dev libssl-dev libcurl4-openssl-dev libasio-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN cmake -S /app -B /app/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /app/build -j


FROM ubuntu:24.04 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsodium23 libssl3 libcurl4 libasio-dev \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements
COPY --from=builder /app/tas_helper/requirements.txt /app/tas_helper/requirements.txt
RUN pip3 install --no-cache-dir -r /app/tas_helper/requirements.txt

# Copy runtime artifacts
COPY --from=builder /app/build/tas_server /app/tas_server
COPY --from=builder /app/tas_helper /app/tas_helper
COPY --from=builder /app/spec /app/spec

ENV TAS_DATA_DIR=/var/lib/tas
ENV TAS_PORT=9000

EXPOSE 9000
ENTRYPOINT ["/app/tas_server"]
