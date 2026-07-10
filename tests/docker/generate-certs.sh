#!/bin/sh
# Regenerate the test PKI under tests/docker/certs/.
set -eu
cd "$(dirname "$0")/certs"

openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.pem -subj "/CN=IRC Test CA"

openssl genrsa -out rogue-ca.key 2048
openssl req -new -x509 -days 3650 -key rogue-ca.key -out rogue-ca.pem -subj "/CN=Rogue CA"

gen_signed() {
  name=$1
  out=$2
  openssl genrsa -out "${out}.key" 2048
  openssl req -new -key "${out}.key" -out "${out}.csr" -subj "/CN=${name}"
  openssl x509 -req -days 3650 -in "${out}.csr" -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out "${out}.pem"
  rm -f "${out}.csr"
}

gen_signed tls-hub.test.net hub
gen_signed tls-leaf.test.net leaf
gen_signed tlspeer.test.net tlspeer
gen_signed tlspeer-ca.test.net tlspeer-ca

openssl genrsa -out expired.key 2048
openssl req -new -key expired.key -out expired.csr -subj "/CN=expired.test.net"
rm -f expired.db expired.attr expired.srl expired.cnf
touch expired.db
echo 'unique_subject = no' > expired.attr
echo 01 > expired.srl
cat > expired.cnf <<'EOF'
[ca]
default_ca = CA_default
[CA_default]
database = expired.db
serial = expired.srl
certificate = ca.pem
private_key = ca.key
new_certs_dir = .
default_md = sha256
policy = policy_any
[policy_any]
commonName = supplied
EOF
openssl ca -config expired.cnf -batch -notext \
  -startdate 20200101000000Z -enddate 20210101000000Z \
  -in expired.csr -out expired.pem
rm -f expired.csr expired.db expired.attr expired.srl expired.cnf

openssl genrsa -out rogue.key 2048
openssl req -new -key rogue.key -out rogue.csr -subj "/CN=rogue.test.net"
openssl x509 -req -days 3650 -in rogue.csr -CA rogue-ca.pem -CAkey rogue-ca.key \
  -CAcreateserial -out rogue.pem
rm -f rogue.csr

openssl genrsa -out selfsigned.key 2048
openssl req -new -x509 -days 3650 -key selfsigned.key -out selfsigned.pem \
  -subj "/CN=selfsigned.test.net"

fp() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 \
    | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f'
}

{
  echo "hub=$(fp hub.pem)"
  echo "leaf=$(fp leaf.pem)"
  echo "tlspeer=$(fp tlspeer.pem)"
  echo "tlspeer-ca=$(fp tlspeer-ca.pem)"
  echo "selfsigned=$(fp selfsigned.pem)"
  echo "expired=$(fp expired.pem)"
  echo "rogue=$(fp rogue.pem)"
} > fingerprints.txt

echo "Wrote certificates and fingerprints.txt"
