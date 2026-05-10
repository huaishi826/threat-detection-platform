#!/usr/bin/env bash
# Generate self-signed SSL certificates for ThreatSight
# Usage: ./generate-ssl.sh [domain]
set -euo pipefail

DOMAIN="${1:-localhost}"
SSL_DIR="$(dirname "$0")/ssl"

mkdir -p "$SSL_DIR"

openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout "$SSL_DIR/key.pem" \
  -out "$SSL_DIR/cert.pem" \
  -subj "/CN=$DOMAIN/O=ThreatSight/C=CN" \
  -addext "subjectAltName=DNS:$DOMAIN,IP:127.0.0.1"

echo "SSL certificates generated in $SSL_DIR/"
echo "  cert.pem  (public certificate)"
echo "  key.pem   (private key)"
echo ""
echo "To use with Docker:"
echo "  docker-compose up --build"
