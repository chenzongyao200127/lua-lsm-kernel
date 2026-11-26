#!/usr/bin/env bash

# SPDX-License-Identifier: GPL-2.0

#
# sandbox.sh — run the reviewer inside a bubblewrap sandbox with no network
# route except loopback, where relay.py forwards to the host-side proxy.
# The sandbox starts with a cleared environment and a dummy key; the real
# credential stays in the host-side proxy (proxy.py).
#
# The workspace is mounted read-only: the agent must not be able to plant
# files (for example git hooks) that a later step would execute on the
# host. Only the output directory is writable.
#
# Usage: sandbox.sh <workspace> <skill-dir> <proxy-socket> <base> <output-dir>
set -euo pipefail

[[ $# -eq 5 ]] || {
    echo "usage: sandbox.sh <workspace> <skill-dir> <proxy-socket> <base> <output-dir>" >&2
    exit 2; }

ws="$1" skill="$2" sock="$3" base="$4" out="$5"
[[ -d "$out" ]] || { echo "sandbox.sh: no such output directory: $out" >&2; exit 2; }
here="$(cd "$(dirname "$0")" && pwd)"

exec bwrap \
    --unshare-all --die-with-parent --new-session --clearenv \
    --cap-drop ALL \
    --ro-bind /usr /usr \
    --symlink usr/bin /bin \
    --symlink usr/sbin /sbin \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --ro-bind /etc/passwd /etc/passwd \
    --ro-bind /etc/group /etc/group \
    --ro-bind /etc/hosts /etc/hosts \
    --ro-bind "$skill" /skill \
    --ro-bind "$here/profile" /profile \
    --ro-bind "$here/relay.py" /relay.py \
    --ro-bind "$sock" /run/proxy.sock \
    --ro-bind "$ws" /work \
    --bind "$out" /out \
    --tmpfs /tmp \
    --dev /dev \
    --tmpfs /dev/shm \
    --proc /proc \
    --chdir /work \
    --setenv HOME /tmp \
    --setenv TMPDIR /tmp \
    --setenv PATH /usr/local/bin:/usr/bin:/bin \
    --setenv LANG C.UTF-8 \
    --setenv DASHSCOPE_API_KEY proxy-injected \
    --setenv LCR_AGENT_PROFILE /profile \
    /usr/bin/bash -c 'python3 /relay.py 8080 /run/proxy.sock & exec /skill/linux_code_review.sh diff "$1" /out/review.md --per-persona-context=no' \
    _ "$base"
