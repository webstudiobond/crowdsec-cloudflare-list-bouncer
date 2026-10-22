FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS builder

WORKDIR /src

COPY go.mod ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -ldflags="-s -w -X 'main.Version=${VERSION}'" \
    -o /bin/crowdsec-cloudflare-list-bouncer \
    ./cmd/crowdsec-cloudflare-list-bouncer

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/crowdsec-cloudflare-list-bouncer /usr/bin/crowdsec-cloudflare-list-bouncer

ENTRYPOINT ["/usr/bin/crowdsec-cloudflare-list-bouncer"]
