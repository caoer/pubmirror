# The publisher image. Its entrypoint, `pubmirror ci`, runs `check` or
# `publish` as the step's mode setting says, and nothing else. The GitHub deploy
# key and the denylist are CI secrets limited to this image; CI withholds them
# from a step that runs commands, which replaces the entrypoint. So what the
# image can do with either is what `check` and `publish` do.
#
# Every base is pinned by digest. Bump a pin by resolving the tag's digest and
# replacing both together.

FROM docker.io/library/golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/pubmirror ./cmd/pubmirror

FROM ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks

FROM docker.io/library/alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache git openssh-client ca-certificates \
 && git config --system safe.directory '*'
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=build /out/pubmirror /usr/local/bin/pubmirror
# GitHub's published host keys (https://api.github.com/meta, ssh_keys). The
# publisher connects with StrictHostKeyChecking=yes against this file.
COPY image/ssh_known_hosts /etc/ssh/ssh_known_hosts
ENTRYPOINT ["/usr/local/bin/pubmirror", "ci"]
