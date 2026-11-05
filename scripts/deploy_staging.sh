#!/usr/bin/env bash
# Placeholder deploy step for the CircleCI workflow. Replace with your real
# target (e.g. push the image to a registry, then restart a staging service).
set -euo pipefail
echo "Deploying sdlcguard:${CIRCLE_SHA1:-local} to staging..."
echo "Secrets must come from CircleCI contexts, never from the repository."
