# syntax=docker/dockerfile:1

FROM golang:1.22-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/ssg ./cmd/ssg

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends systemd ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/ssg /usr/local/bin/ssg
WORKDIR /github/workspace
ENTRYPOINT ["ssg"]

