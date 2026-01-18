
## Split the star_liveaction_com.pem file

/tmp/cert-2.pem came from splitting your original PEM file (/home/mandrews/.ssh/star_liveaction_com.pem) into separate certificate files—one per -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE----- block.

> awk 'BEGIN{c=0} /BEGIN CERTIFICATE/{c++} {print > ("/tmp/cert-" c ".pem")}' /home/mandrews/.ssh/star_liveaction_com.pem


How that works:

c starts at 0.

Every time awk sees a line containing BEGIN CERTIFICATE, it increments c.

Every line (including the BEGIN/END lines and base64 body) is written to /tmp/cert-${c}.pem.

Because your star_liveaction_com.pem contains two certificates concatenated together:

/tmp/cert-1.pem became the first certificate block: the leaf/server cert CN=*.liveaction.com

/tmp/cert-2.pem became the second certificate block: the intermediate CA DigiCert Global G2 TLS RSA SHA256 2020 CA1

You then confirmed that by running openssl x509 -subject -issuer on each file, which showed /tmp/cert-2.pem is the intermediate CA.


## Use the existing DigiCert Global Root G2 cert file (often present)

#### 1) Look for a DigiCert Global Root G2 cert file in the system cert directory
> ls -1 /etc/ssl/certs | grep -i "digicert.*global.*root.*g2" || true  

#### 2) If you see a matching file (example: DigiCert_Global_Root_G2.pem), copy it to your pinned location  
```
ROOT_SRC="/etc/ssl/certs/DigiCert_Global_Root_G2.pem"
ROOT="/home/mandrews/clickhouse-pin-root-g2.pem"
cp "$ROOT_SRC" "$ROOT"
chmod 0644 "$ROOT"
```

#### 3) Build your pinned CA bundle (root + intermediate CA from your earlier split: /tmp/cert-2.pem)
```
PINNED="/home/mandrews/clickhouse-pinned-ca-bundle.pem"
cat "$ROOT" /tmp/cert-2.pem > "$PINNED"
chmod 0644 "$PINNED"
```

#### 4) Sanity checks
> openssl x509 -in "$ROOT" -noout -subject -issuer  
openssl verify -CAfile "$PINNED" /tmp/cert-1.pem
