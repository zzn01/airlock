# Multi-stage build producing a minimal, non-root image for the airlock gateway.

# --- build stage -------------------------------------------------------------
FROM golang:1.26 AS build
WORKDIR /src

# The module is pure stdlib (no external deps), so there is nothing to download;
# copying go.mod first still lets this layer cache across source-only changes.
COPY go.mod ./
COPY . .

# Static, stripped binary so it runs on the distroless static base.
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN go build -ldflags="-s -w" -o /out/airlock ./cmd/airlock

# --- runtime stage -----------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/airlock /usr/local/bin/airlock

# Config path and listen address are overridable at runtime via env vars.
ENV AIRLOCK_CONFIG=/etc/airlock/airlock.json \
    AIRLOCK_LISTEN=:8080

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/airlock"]
