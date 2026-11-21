# kube-policy-mcp as a small image: one static binary. Nothing else, not
# even a shell. Policies and the config file are mounted in; see
# deploy/compose.yaml.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# The build has no git history to read the version from, so it is passed in:
#   docker build --build-arg VERSION=1.2.3 .
ARG VERSION=dev
# Leave engines out with build tags, for a smaller image:
#   docker build --build-arg TAGS="no_vap no_gatekeeper" .
ARG TAGS=""
RUN CGO_ENABLED=0 go build -trimpath -tags "${TAGS}" \
    -ldflags="-s -w -X github.com/cosmosdevops/kube-policy-mcp/internal/app.Version=${VERSION}" \
    -o /kube-policy-mcp ./cmd/kube-policy-mcp

FROM scratch
COPY --from=build /kube-policy-mcp /kube-policy-mcp
# The config file is looked for here unless --config says otherwise. Mount
# a directory holding it, and the policies it names, at /config.
ENV KUBE_POLICY_MCP_CONFIG=/config/kube-policy-mcp.yaml
# Runs as an unprivileged user. Files it must read (the config, the
# policies and the API keys) need to be readable by this ID; see
# deploy/compose.yaml.
USER 65532:65532
EXPOSE 8088
ENTRYPOINT ["/kube-policy-mcp"]
# With no arguments it talks MCP over stdin/stdout, as "serve" does:
#   docker run --rm -i -v /etc/kube-policy-mcp:/config:ro ghcr.io/cosmosdevops/kube-policy-mcp
CMD ["serve"]
