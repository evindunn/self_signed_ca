#!/bin/bash

# Despite my best efforts to keep this both simple and portable, this will 
# only run properly on OSX

set -eo pipefail

COLOR_RED=$'\033[0;31m'
COLOR_GREEN=$'\033[0;32m'
COLOR_RESET=$'\033[0m'

original_dir="$(pwd)"

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"; cd "$original_dir"' EXIT

cd "$temp_dir"

format_asn1_utc() {
    python3 -c 'import datetime; import sys; print(datetime.datetime.fromisoformat(sys.argv[1]).strftime("%b %e %H:%M:%S %Y GMT"))' "$1"
}

print_success() {
    printf "%sSUCCESS: %s%s\n" "$COLOR_GREEN" "$1" "$COLOR_RESET"
}

print_error() {
    printf "%sERROR: %s%s\n" "$COLOR_RED" "$1" "$COLOR_RESET"
}

extract_cert_field() {
    openssl x509 -noout -in test.localdomain.net.crt "$1" | grep -E "^$2" | sed -E "s/^$2=[[:space:]]*//"
}

now_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ssca test.localdomain.net US NY Syracuse MyOrg noreply@evindunn.com
printf "\n"

one_minute_ago=$(python3 -c 'import datetime; import sys; now = datetime.datetime.fromisoformat(sys.argv[1]); print((now - datetime.timedelta(minutes=1)).isoformat())' "$now_iso")
not_after_iso=$(python3 -c 'import datetime; import sys; now = datetime.datetime.fromisoformat(sys.argv[1]); print((now + datetime.timedelta(days=365)).isoformat())' "$now_iso")

EXPECTED_SUBJECT="/C=US/ST=NY/L=Syracuse/O=MyOrg/emailAddress=noreply@evindunn.com/CN=test.localdomain.net"
EXPECTED_ISSUER="$EXPECTED_SUBJECT"
EXPECTED_NOT_BEFORE="$(format_asn1_utc "$one_minute_ago")"
EXPECTED_NOT_AFTER="$(format_asn1_utc "$not_after_iso")"

keyhash=$(openssl rsa -noout -modulus -in test.localdomain.net.key | openssl md5)
crthash=$(openssl x509 -noout -modulus -in test.localdomain.net.crt | openssl md5)

if [ "$keyhash" != "$crthash" ]; then
    print_error 'Key and certificate do not match'
    printf "\n"
    exit 1
else
    print_success 'Key and certificate match'
fi

ACTUAL_SUBJECT=$(extract_cert_field '-subject' 'subject')
ACTUAL_ISSUER=$(extract_cert_field '-issuer' 'issuer')
ACTUAL_NOT_BEFORE=$(extract_cert_field '-dates' 'notBefore')
ACTUAL_NOT_AFTER=$(extract_cert_field '-dates' 'notAfter')

for field in SUBJECT ISSUER NOT_BEFORE NOT_AFTER; do
    expected_var="EXPECTED_${field}"
    actual_var="ACTUAL_${field}"
    expected_value="${!expected_var}"
    actual_value="${!actual_var}"

    if [ "$actual_value" != "$expected_value" ]; then
        print_error "${field} does not match expected value"
        echo   "Expected: $expected_value"
        printf "Actual:   %s\n\n" "$actual_value"
        exit 1
    else
        print_success "$field matches expected value"
    fi
done
