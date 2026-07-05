# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS build

# gcc + musl-dev required for go-sqlite3 (CGO)
RUN apk add --no-cache gcc musl-dev

WORKDIR /src

# Cache module downloads before copying source
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux \
    go build -ldflags="-s -w" -o /out/cipher-shield ./cmd/server && \
    CGO_ENABLED=1 GOOS=linux \
    go build -ldflags="-s -w" -o /out/cipher-shield-proxy ./cmd/proxy

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=build /out/cipher-shield /usr/local/bin/cipher-shield
COPY --from=build /out/cipher-shield-proxy /usr/local/bin/cipher-shield-proxy

# Proxy port + API/dashboard port
EXPOSE 7070 8080

ENTRYPOINT ["cipher-shield"]
