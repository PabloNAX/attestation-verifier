#!/usr/bin/env bash
# Runs the verifier against a chain you supply, plus a set of negative cases
# derived from it. No sample chains are bundled: see "Producing your own test
# evidence" in the README.
#
# Usage: ./test.sh <chain.pem> <nonceBase64> [packageName]

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ $# -lt 2 ]; then
  echo "usage: ./test.sh <chain.pem> <nonceBase64> [packageName]"
  echo
  echo "Generate a chain with the Kotlin snippet in the README, then pass it here"
  echo "together with the nonce you used."
  exit 2
fi

CHAIN="$1"
NONCE="$2"
PACKAGE="${3:-}"
ROOTS="$HERE/roots/GoogleAttestationRoots.pem"

DLL="$HERE/tools/VerifyCli/bin/Debug/net8.0/verify-attestation.dll"
[ -f "$DLL" ] || dotnet build "$HERE/tools/VerifyCli/VerifyCli.csproj" -v q --nologo || exit 1

pass=0
fail=0

expect() {
  local name="$1" want="$2"; shift 2
  local out got
  out="$(dotnet "$DLL" "$@" 2>&1)"
  got="$(printf '%s' "$out" | grep -E '^RESULT' | head -1)"
  if printf '%s' "$got" | grep -q "$want"; then
    printf '  ok    %-42s %s\n' "$name" "$want"
    pass=$((pass+1))
  else
    printf '  FAIL  %-42s expected %s\n' "$name" "$want"
    printf '%s\n' "$out" | sed 's/^/          /'
    fail=$((fail+1))
  fi
}

echo "chain: $CHAIN"
echo

expect "valid chain"            "accepted"            "$CHAIN" "$ROOTS" "$NONCE" "$PACKAGE"
expect "wrong nonce"            "NONCE_MISMATCH"      "$CHAIN" "$ROOTS" "AAAAqgd2DEGBbBE6R55A5PqyKUUqjhoY8ujHIQw4UsI=" "$PACKAGE"

if [ -n "$PACKAGE" ]; then
  expect "wrong package"        "ATTESTATION_INVALID" "$CHAIN" "$ROOTS" "$NONCE" "com.example.not.your.app"
fi

: > /tmp/attest-empty-roots.pem
expect "empty trust anchors"    "CONFIG_ERROR"        "$CHAIN" /tmp/attest-empty-roots.pem "$NONCE" "$PACKAGE"

# Only one of the two Google roots. Whichever one your device does not chain
# through, this must reject.
awk 'BEGIN{n=0} /BEGIN CERT/{n++} n==2{print}' "$ROOTS" > /tmp/attest-one-root.pem
expect "one root instead of two" "ATTESTATION_INVALID" "$CHAIN" /tmp/attest-one-root.pem "$NONCE" "$PACKAGE"

# The case that carries the whole design: edit the attested content and the
# signature over it stops matching.
python3 - "$CHAIN" "$PACKAGE" > /tmp/attest-tampered.pem <<'PY'
import sys, base64, re
raw = open(sys.argv[1]).read().replace('\\n', '\n')
target = (sys.argv[2] or '').encode()
blocks = re.findall(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', raw, re.S)
der = bytearray(base64.b64decode(''.join(blocks[0].split())))
i = der.find(target) if target else -1
if i < 0:
    i = 200  # no package supplied, flip a byte in the middle of the body instead
    der[i] ^= 0xFF
else:
    der[i:i+3] = b'xxx'
out = []
for j, b in enumerate(blocks):
    body = base64.b64encode(bytes(der)).decode() if j == 0 else ''.join(b.split())
    out.append('-----BEGIN CERTIFICATE-----\n' + body + '\n-----END CERTIFICATE-----')
print('\n'.join(out))
PY
expect "leaf content edited"    "ATTESTATION_INVALID" /tmp/attest-tampered.pem "$ROOTS" "$NONCE" "$PACKAGE"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
