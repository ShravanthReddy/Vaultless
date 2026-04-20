FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o vaultless ./cmd/vaultless/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates git
COPY --from=builder /build/vaultless /usr/local/bin/vaultless
ENTRYPOINT ["vaultless"]
