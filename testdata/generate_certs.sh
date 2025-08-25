#!/bin/bash
# 1. Create Root CA with CA capabilities
openssl req -new -x509 -days 3650 -nodes -newkey rsa:2048 \
  -keyout root-ca.key -out root-ca.crt \
  -subj "/CN=Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2. Create Intermediate CA key and CSR
openssl req -new -nodes -newkey rsa:2048 \
  -keyout intermediate-ca.key -out intermediate-ca.csr \
  -subj "/CN=Intermediate CA"

# 3. Sign Intermediate with Root (create intermediate cert)
openssl x509 -req -in intermediate-ca.csr \
  -CA root-ca.crt -CAkey root-ca.key -CAcreateserial \
  -out intermediate-ca.crt -days 3650 \
  -extfile <(echo -e "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign")

# 4. Create chain file
cat intermediate-ca.crt root-ca.crt > ca-chain.crt

# 5. Issue a test server cert from intermediate WITH SANs
openssl req -new -nodes -newkey rsa:2048 \
  -keyout server.key -out server.csr \
  -subj "/CN=localhost"

openssl x509 -req -in server.csr \
  -CA intermediate-ca.crt -CAkey intermediate-ca.key -CAcreateserial \
  -out server.crt -days 3650 \
  -extfile <(echo "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1,IP:::1")
