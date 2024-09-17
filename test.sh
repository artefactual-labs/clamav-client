#!/usr/bin/env bash

set -euo pipefail

print_status() {
  echo -en "\n➡️  $1\n\n"
}

if ! command -v uv > /dev/null; then
  echo "Error: 'uv' is not installed or not in the PATH."
  echo "To install it, run:"
  echo "  $ curl -LsSf https://astral.sh/uv/install.sh | sh"
  exit 1
fi

versions=(
  "3.8"
  "3.9"
  "3.10"
  "3.11"
  "3.12"
)

latest="${versions[${#versions[@]}-1]}"

markers=""
if [[ " $@ " =~ " --fast " ]]; then
  markers="not slow"
fi

if [[ " $@ " =~ " --latest " ]]; then
  versions=("3.12")
fi

for version in "${versions[@]}"; do
  print_status "Running \`pytest\` using Python $version..."
  uv run --frozen --python "$version" -- pytest -m "$markers" --cov clamav_client --cov-report xml:coverage.xml --cov-report html --cov-append
done

print_status "Running \`ruff check\` using Python $latest..."
uv run --frozen --python "$latest" -- ruff check

print_status "Running \`ruff format --check\` using Python $latest..."
uv run --frozen --python "$latest" -- ruff format --check

print_status "Running \`mypy\` using Python $latest..."
uv run --frozen --python "$latest" -- mypy
