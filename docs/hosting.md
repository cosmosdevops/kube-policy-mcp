# Hosting

One copy of the server can serve many agents over HTTP. Each caller needs an
API key, and each key has its own rate limit.

```bash
kube-policy-mcp serve --config /etc/kube-policy-mcp/kube-policy-mcp.yaml --http 127.0.0.1:8088 --keys /etc/kube-policy-mcp/keys
```

MCP is served at `/mcp`. `/healthz` is open and needs no key.

Serve it over HTTPS only, because the key travels in a header on every
request. Listen on `127.0.0.1` and put a reverse proxy with TLS in front.

## API keys

Make a key for each person or team:

```bash
sudo sh -c 'kube-policy-mcp new-key alice >> /etc/kube-policy-mcp/keys'
```

The key is printed once, for you to pass on. The line added to the keys file
holds the name and the SHA-256 of the key, never the key itself. A lost key
cannot be recovered: make a new one.

```text
# /etc/kube-policy-mcp/keys
alice 5f2b…e91c
ci-pipeline 9a40…77d2
```

To revoke a key, delete its line. The server re-reads the file within a few
seconds, with no restart. If an edit leaves the file broken, the server keeps
the keys it had and logs why.

## Rate limits

Each key may make 60 requests a minute, with a burst of 30. Change this with
`--rate` and `--burst`. One key's use does not affect another's.

| Response | Meaning |
| --- | --- |
| `401` | No key, or a key that is not in the file. |
| `429` | Over the limit. `Retry-After` says how long to wait. |

## Connecting an agent

```bash
claude mcp add --transport http kube-policy https://example.com/mcp --header "Authorization: Bearer <key>"
```

Or in `.mcp.json`:

```json
{
  "mcpServers": {
    "kube-policy": {
      "type": "http",
      "url": "https://example.com/mcp",
      "headers": {"Authorization": "Bearer <key>"}
    }
  }
}
```

## What a hosted server exposes

- Callers send manifests inline. The `files` and `evaluate_directory` inputs
  read from the server's own `workspaceRoots`. The config in
  [deploy/kube-policy-mcp.yaml](../deploy/kube-policy-mcp.yaml) has none, so
  those inputs are refused and nobody can read files from the server.
- Each key holder sees only their own evaluations. `explain_violation` cannot
  read a finding from someone else's evaluation.
- The log has one line per request: the key's name, the status and the time
  taken. The request body is never logged.
- Every call stands alone, so the server can sit behind a proxy or a load
  balancer. The history that `explain_violation` uses is kept in memory per
  process. With several copies, an explanation may need the evaluation to be
  run again.

## Set up with systemd

The files in [deploy](../deploy) run the server as a systemd service behind
Apache. Everything it needs is in one directory:

```text
/etc/kube-policy-mcp/kube-policy-mcp.yaml   the config (start from deploy/kube-policy-mcp.yaml)
/etc/kube-policy-mcp/policies/              your policy sources
/etc/kube-policy-mcp/keys                   the API keys
```

```sh
CGO_ENABLED=0 go build -trimpath -o kube-policy-mcp ./cmd/kube-policy-mcp   # on any machine
sudo install -m 755 kube-policy-mcp /usr/local/bin/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin kube-policy-mcp
sudo install -d -m 750 -o root -g kube-policy-mcp /etc/kube-policy-mcp
sudo install -m 640 -o root -g kube-policy-mcp deploy/kube-policy-mcp.yaml /etc/kube-policy-mcp/
sudo cp -r examples/policies /etc/kube-policy-mcp/policies            # or your own policies
sudo chgrp -R kube-policy-mcp /etc/kube-policy-mcp/policies
sudo install -m 640 -o root -g kube-policy-mcp /dev/null /etc/kube-policy-mcp/keys
sudo install -m 644 deploy/kube-policy-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now kube-policy-mcp
curl http://127.0.0.1:8088/healthz                  # prints ok
```

Then route `/mcp` to it from Apache. Copy `deploy/kube-policy-mcp-apache.conf`
to `/etc/apache2/` and include it in the site's HTTPS `<VirtualHost>`:

```sh
sudo a2enmod proxy proxy_http
sudo apachectl configtest && sudo systemctl reload apache2
```

## Set up with Docker

The image is `ghcr.io/cosmosdevops/kube-policy-mcp`, built from every commit
on `master`. It holds the program and the licences of the code built into it,
and nothing else. It runs as an unprivileged user (ID 65532).

Make the config directory readable by that user, then start the compose file
from `deploy/`:

```sh
sudo install -d -m 750 -o root -g 65532 /etc/kube-policy-mcp
sudo install -m 640 -o root -g 65532 deploy/kube-policy-mcp.yaml /etc/kube-policy-mcp/
sudo cp -r examples/policies /etc/kube-policy-mcp/policies            # or your own policies
sudo chgrp -R 65532 /etc/kube-policy-mcp/policies
sudo install -m 640 -o root -g 65532 /dev/null /etc/kube-policy-mcp/keys
docker compose -f deploy/compose.yaml up -d
curl http://127.0.0.1:8088/healthz                  # prints ok
```

The compose file mounts the config directory read-only, runs the container
with a read-only file system and no capabilities, and publishes the port on
localhost only. Route `/mcp` to it from Apache as above.

Make keys with the image too:

```sh
sudo sh -c 'docker run --rm ghcr.io/cosmosdevops/kube-policy-mcp new-key alice >> /etc/kube-policy-mcp/keys'
```

To update, pull and start again. Only the short history used by
`explain_violation` is lost.

```sh
docker compose -f deploy/compose.yaml pull && docker compose -f deploy/compose.yaml up -d
```

The container has no shell or curl, so its health check uses the program
itself: `kube-policy-mcp check-health http://127.0.0.1:8088/healthz` exits 0
when the server is up.

### Building the image

```sh
docker build --build-arg VERSION=1.2.3 -t kube-policy-mcp:local .
```

Leave engines out for a smaller image:

```sh
docker build --build-arg TAGS="no_vap no_gatekeeper" -t kube-policy-mcp:opa .
```

### Podman and SELinux

The image and the compose file run unchanged with `podman` and
`podman-compose`.

- As root (`sudo podman …`), set up the config directory exactly as above.
- Rootless, user IDs inside the container are shifted, so ID 65532 cannot
  read a file that only your own user can. Map the container's user onto
  yours with `--userns=keep-id:uid=65532,gid=65532` (in compose:
  `userns_mode: "keep-id:uid=65532,gid=65532"`), and have your own user own
  the config directory.

On a host with SELinux (Fedora, RHEL), add `,z` to the volume line, as in
`/etc/kube-policy-mcp:/config:ro,z`.

### Using the image locally

The image also works over stdio, with no Go needed. Mount a directory that
holds your config and policies at `/config`:

```json
{
  "mcpServers": {
    "kube-policy": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-v", "/etc/kube-policy-mcp:/config:ro", "ghcr.io/cosmosdevops/kube-policy-mcp"]
    }
  }
}
```
