FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

COPY go.mod go.sum ./
COPY third_party/ third_party/
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o sopsgate ./cmd/server

FROM alpine:3.21

RUN apk add --no-cache git ca-certificates

COPY --from=builder /build/sopsgate /usr/local/bin/sopsgate

WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["sopsgate"]
CMD ["-config", "/app/config.yaml"]
