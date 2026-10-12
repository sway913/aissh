# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=arm64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -tags noweb -o /aisshs ./cmd/aisshs
FROM alpine:3.22
RUN apk add --no-cache ca-certificates && addgroup -g 10001 aissh && adduser -D -u 10001 -G aissh aissh
COPY --from=build /aisshs /usr/local/bin/aisshs
USER 10001:10001
EXPOSE 17443 17000
ENTRYPOINT ["/usr/local/bin/aisshs"]
CMD ["--data-dir", "/data", "--api-addr", "0.0.0.0:17443", "--federation-config", "/data/federation.json"]
