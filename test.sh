#!/usr/bin/env bash

set -euo pipefail

versions=(
  "3.8"
  "3.9"
  "3.10"
  "3.11"
  "3.12"
)

prereleases=(
  "3.13"
)

print_status() {
  echo -en "\n➡️  $1\n\n"
}

if ! command -v uv > /dev/null; then
  echo "Error: 'uv' is not installed or not in the PATH."
  echo "To install it, run:"
  echo "  $ curl -LsSf https://astral.sh/uv/install.sh | sh"
  exit 1
fi

curdir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

markers=""
if [[ " $@ " =~ " --fast " ]]; then
  markers="not slow"
fi

latest="${versions[${#versions[@]}-1]}"

if [[ " $@ " =~ " --latest " ]]; then
  versions=("3.12")
  prereleases=()
elif [[ " $@ " =~ " --pre " ]]; then
  versions=()
  prereleases=("3.13")
fi

combined=("${versions[@]}" "${prereleases[@]}")

for version in "${combined[@]}"; do
  print_status "Running \`pytest\` using Python $version..."
  env \
    UV_PROJECT_ENVIRONMENT="$curdir/.venv/test-runner/$version/" \
    VIRTUAL_ENV="$curdir/.venv/test-runner/$version/" \
      uv run --frozen --python "$version" -- \
        pytest -m "$markers" \
          --junitxml=junit.xml \
          --override-ini=junit_family=legacy \
          --cov \
          --cov-append \
          --cov-report xml:coverage.xml \
          --cov-report html
done

print_status "Running \`ruff check\` using Python $latest..."
uv run --frozen --python "$latest" -- ruff check

print_status "Running \`ruff format --check\` using Python $latest..."
uv run --frozen --python "$latest" -- ruff format --check

print_status "Running \`mypy\` using Python $latest..."
uv run --frozen --python "$latest" -- mypy
