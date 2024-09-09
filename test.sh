#!/usr/bin/env bash

set -euo pipefail

if ! command -v uv > /dev/null; then
  echo "Error: 'uv' is not installed or not in the PATH."
  exit 1
fi

versions=(
  "3.8"
  "3.9"
  "3.10"
  "3.11"
  "3.12"
)

print_status() {
  echo -en "\n➡️  $1\n\n"
}

for version in "${versions[@]}"; do
  print_status "Running \`pytest\` using Python $version..."
  uv run --frozen --python "$version" -- pytest
done

latest="${versions[${#versions[@]}-1]}"

print_status "Running \`ruff check\` using Python $latest..."
uv run --frozen --python "$latest" -- ruff check

print_status "Running \`ruff format --check\` using Python $latest..."
uv run --frozen --python "$latest" -- ruff format --check

print_status "Running \`mypy\` using Python $latest..."
uv run --frozen --python "$latest" -- mypy
