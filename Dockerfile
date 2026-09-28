# ---- build stage ----
FROM golang:1.26-alpine AS builder
WORKDIR /src

# Cache module downloads (no external deps here, but keeps the pattern).
COPY go.mod ./
RUN go mod download

COPY . .

# Build both binaries as fully static binaries.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

# ---- runtime stage ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/server /usr/local/bin/server
COPY --from=builder /out/client /usr/local/bin/client

WORKDIR /work
EXPOSE 8080

# Default entrypoint runs the server; docker-compose overrides it for the client.
ENTRYPOINT ["server"]
