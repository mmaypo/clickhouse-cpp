#!/bin/bash

# Step 1, client private service key
ENV="prod"
SERVICE="svc_livewire"
URI="spiffe://bluecatnetworks.com/clickhouse/${ENV}/${SERVICE}"

# Key
openssl genrsa -out "${SERVICE}.key" 2048
chmod 600 "${SERVICE}.key"

# Step 2, CSR with SAN URI
openssl req -new -key "${SERVICE}.key" \
  -subj "/CN=${SERVICE}" \
  -out "${SERVICE}.csr" \
  -addext "subjectAltName = URI:${URI}" \
  -addext "extendedKeyUsage = clientAuth"

# Step 3, sign the CSR
openssl x509 -req -in "${SERVICE}.csr" \
  -CA ch_client_ca.crt -CAkey ch_client_ca.key -CAcreateserial \
  -out "${SERVICE}.crt" -days 825 -sha256 \
  -copy_extensions copy
chmod 644 "${SERVICE}.crt"
