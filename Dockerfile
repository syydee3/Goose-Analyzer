FROM golang:1.26.2-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN mkdir -p /out && \
    CGO_ENABLED=1 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/analyzer ./cmd/analyzer && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN mkdir -p /app/bin /app/uploads /app/configs /app/templates /root/dumps

COPY --from=builder /out/analyzer /app/bin/analyzer
COPY --from=builder /out/server /app/bin/server
COPY templates/index.html /app/templates/index.html

ENV TCP_ADDR="0.0.0.0:5514" \
    HTTP_ADDR="0.0.0.0:5000" \
    UPLOAD_DIR="/app/uploads" \
    CONFIG_DIR="/app/configs" \
    HISTORY_FILE="/app/configs/history.json" \
    ANALYZER_BIN="/app/bin/analyzer" \
    ANALYZER_IFACE="eth0"

EXPOSE 5000 5514

CMD ["/app/bin/server"]