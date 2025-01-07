#!/bin/bash

# Arguments
binary_path=$1
os=$2
arch=$3

# Define excluded types
exclude=(
  "windows_arm64"
  "windows_arm"
)

# Create a combined identifier
identifier="${os}_${arch}"

# Check if identifier is in the excluded list
if [[ " ${excluded[*]} " == *" ${identifier} "* ]]; then
  echo "Skipping binary: $binary_path (excluded: $identifier)"
else
  echo "Packing binary: $binary_path"
  if command -v upx >/dev/null 2>&1; then
    upx "$binary_path"
  else
    echo "UPX is not installed, skipping packing for $binary_path"
  fi
fi
