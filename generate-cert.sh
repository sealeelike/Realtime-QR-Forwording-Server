#!/bin/bash
# Generate self-signed certificate for HTTPS

mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=localhost"

echo "Certificates generated in ./certs/"
echo "Note: Browser will show security warning for self-signed certificates."
echo "You can add an exception to proceed."
