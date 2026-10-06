#!/bin/sh
set -eu
exec sudo -u defense-ai python3 /opt/defense-agent/console.py "$@"
