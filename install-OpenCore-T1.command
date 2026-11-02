#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Installing BridgePatcher T1 for MacBookPro14,3..."
sudo installer -pkg "${DIR}/BridgePatcher.pkg" -target /
