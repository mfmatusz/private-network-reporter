FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN apk add --no-cache build-base
# Build new modular version from cmd/pnr
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/pnr ./cmd/pnr

FROM alpine:3.20
RUN apk add --no-cache nmap nmap-scripts ca-certificates tzdata
COPY --from=build /out/pnr /usr/local/bin/pnr
# /data będzie na volume (automatyczne self-signed certs jeśli TLS_ENABLED=true)
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["pnr"]
