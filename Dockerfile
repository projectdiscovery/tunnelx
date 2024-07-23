# Base
FROM golang:1.21.4-alpine AS builder
RUN apk add --no-cache build-base
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build .

# Release
FROM alpine:3.18.2
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/tunnelx /usr/local/bin/

ENTRYPOINT ["tunnelx"]