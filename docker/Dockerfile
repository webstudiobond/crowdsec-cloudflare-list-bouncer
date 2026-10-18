FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder

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
