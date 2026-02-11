#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of trustee-tests/Functional/kbs-fake-token-get-resource
#   Description: Tests KBS package with external JWT token validation using a pre-signed static token.
#   Author: Patrik Koncity <pkoncity@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2026 Red Hat, Inc.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation, either version 2 of
#   the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE.  See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see http://www.gnu.org/licenses/.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# This test uses fully hardcoded static keys and pre-signed token.
#
# Components used:
#   - /usr/bin/kbs (from trustee-kbs RPM) - KBS server
#
# Architecture:
#   curl + JWT token -> KBS -> LocalFs resources
. /usr/share/beakerlib/beakerlib.sh || exit 1

# Should be set in main.fmf
HTTP_MODE="${HTTP_MODE:-http}"

# Curl options for HTTPS (skip cert verification for self-signed)
if [[ "$HTTP_MODE" == "https" ]]; then
    CURL_OPTS="-k"
else
    CURL_OPTS=""
fi

# Server settings
SERVER_IP="127.0.0.1"
KBS_PORT="8080"
KBS_WORK_DIR="/var/lib/kbs"
KBS_REPO_DIR="${KBS_WORK_DIR}/repository"
KBS_CONFIG="kbs-config.toml"
KBS_PID=""

# Pre-signed JWT token (expires year 2099)
# Header: {"alg":"EdDSA","typ":"JWT","kid":"test-key-1"}
# Payload: {"exp":4102444800,"tee":"sample","sub":"test","tee-pubkey":{...}}
STATIC_TOKEN="eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LTEifQ.eyJleHAiOjQxMDI0NDQ4MDAsInRlZSI6InNhbXBsZSIsInN1YiI6InRlc3QiLCJ0ZWUtcHVia2V5Ijp7Imt0eSI6IlJTQSIsImFsZyI6IlJTQS1PQUVQLTI1NiIsIm4iOiI1N2d4YmRIVmMzNU1CYThDZEhoSG0xM0owclo2MkpNUi0tcWRubENkNVBtWW5RQmVTbDJSTUN3THZZVXZuRmd6ek1xYUJuN1ZJSVY3S3FNS0lVZTN1MTk3YjVwbHZ2emFCSTFrb29TRHVIVFVoN2xIRXZzNE9sZEJ4TFZIS3lGMnRBc1BpZGd2VV9oNUY3dkFoTW1FcjZFZWNBVTJRUFNIV21DeXhPc2R3b2Q0Mlhkd2NkaWVCY0gxRlBmc0tBLVZmcEFySmNOV0oxUGRaTkpzUjZxNWpCR1M3TWhrdWZKaTNVRzIzSEljSC1wRjI3YUZNazdHZHhfUkxqUkZPQlVOWmtVSGt2LTBXYnMtTXBKMzZJUzBUTnhtSkdaQzE5VFlCdmdNSlVXQy1IQzBUcTVEdzRRd2M0WWthVnlUcUlRcEcydy1EVjl4Y0FUM2ZaVkhENGlnenciLCJlIjoiQVFBQiJ9fQ.c_TcU9uLnQoADGshVTLb26mqtFsjddaeT5F4rvNO6Ml3TAX-EYdJWKkQUW4S2R2FmQHYugQA2i6RL8jKcdAvDw"

# Ed25519 public key X value for JWK (base64url, corresponds to private key used for signing)
ED25519_X="SHiAhbAmKH5cy00kGGux0YGtDWKs9nEizs3Br8FZUuY"

# RSA private key for TEE (used to decrypt KBS responses)
RSA_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA57gxbdHVc35MBa8CdHhHm13J0rZ62JMR++qdnlCd5PmYnQBe
Sl2RMCwLvYUvnFgzzMqaBn7VIIV7KqMKIUe3u197b5plvvzaBI1kooSDuHTUh7lH
Evs4OldBxLVHKyF2tAsPidgvU/h5F7vAhMmEr6EecAU2QPSHWmCyxOsdwod42Xdw
cdieBcH1FPfsKA+VfpArJcNWJ1PdZNJsR6q5jBGS7MhkufJi3UG23HIcH+pF27aF
Mk7Gdx/RLjRFOBUNZkUHkv+0Wbs+MpJ36IS0TNxmJGZC19TYBvgMJUWC+HC0Tq5D
w4Qwc4YkaVyTqIQpG2w+DV9xcAT3fZVHD4igzwIDAQABAoIBADcqAIp2c+xk2tBX
k6wKnnF8aHnDe4dnq9ZfSlrQMma6jPyDg+8MS24+biUWOflsfhh4+yYkt7RgUqwZ
2GWH31O6LXaqOSK4q2Z+CsEt7vXQym/tSeBY8k/hSgT8aw73jnzaTT6xusKw2pMt
3W0/VFlDcC2W8A2SqU54ytZaauFOTx0Odb4Y9nJVBMXyb6v2cE8Sv3W6HX+Js9RQ
4Dpi26e0yscjs7+6EOlASd8AjYhQ2pxSrBBZsc/r2J57+5L40+UOLkjsHgkCrtmF
/wKqc7TFw2IWJR1RhyjJE5XQoyKr0dukXlQ5Usc0jYRueAKbGU8LwA9GJoUtOICC
jeNHC7ECgYEA9POQaCu4XbKN6C72p55dJWRaEnFOeafExir1s3bE1R3XABSGpd5Q
b583LCJjIZ0flerh9UZPtQom79C5rTHD9OA0NTNPbHoXZI0r9OuwSg8T/ibfrB01
FI5JFnC/U2fqEDVe+tO64oe8/js8FIa38r9y+LOxgOL7QJ9k/q3odfsCgYEA8ivX
TNnSEus3m/YyRMs6uDUzqMsjuCS8jTuwNs9We//1a/Vjy1ZmxZsnd6wSYfdqIGIG
iPsYh+YaT7AqhWb0Ru2IxrS1hAHjc1JLsSY4TT6UQjA8E3j7HcbZFv/Er22gZKQW
DcJXalTPE7ilETZrxEEtoKlJ0gr1VzZ63h/6TD0CgYBQklE8wqzJPTNKXTBK4F95
LjImgNi0UYf7OyRInNeP1lnjL90+cAr7PF7UiJcc9mbuVC1xFWigfy9hkMGSg50W
Ti0+FpuYbeyF6Z282U3Kfn0wCy9lmNHd6hOGax2z3Kl0HWoZjU2at9VltqxDgDC/
i1PRFKJdZ8wHbKa20xN0wwKBgGMxifK0ldOh/Rko8tYy2E5znEFbU7otcf33oOoS
az5HTWN3E/VJ4ra2IqhmFvGBwjqZbEvXbejcW5KgegpCbXRP/2JEysTTcTLfVpmt
KgqZw2iJEVJ4j4NW270L7qhcowIWI+Jm5B9ttZRCYXp3bBTrDaFtNguO6YdbjWBG
gOORAoGBAI/2kpTDCNB+YEDFALMHYyTD4sPwXQx1yNb2xydZOsjw64OCrZiueHuR
X/qyL06YFSaHO+b6J3OVsxIex/cxNrbZBkHLF02wNGQXzIaSacBC6uvMedcaYFiv
YEi3MgSZfg+7Fq0apArs26uow+bt62crmpHNqHEQGD6sbhtrYEIq
-----END RSA PRIVATE KEY-----"

# Decrypt JWE response from KBS and verify the secret
kbsDecryptResources() {
    RESPONSE="$1"
    rlLog "Retrieved encrypted resource (JWE format)"

    # Extract JWE components
    PROTECTED=$(echo "$RESPONSE" | jq -r '.protected')
    ENCRYPTED_KEY=$(echo "$RESPONSE" | jq -r '.encrypted_key')
    IV=$(echo "$RESPONSE" | jq -r '.iv')
    CIPHERTEXT=$(echo "$RESPONSE" | jq -r '.ciphertext')
    TAG=$(echo "$RESPONSE" | jq -r '.tag')

    # Save protected header for AAD (JWE uses it as Additional Authenticated Data)
    echo -n "$PROTECTED" > ${KBS_WORK_DIR}/protected.txt

    # Decode base64url to binary
    echo -n "$ENCRYPTED_KEY" | tr '_-' '/+' | base64 -d > ${KBS_WORK_DIR}/encrypted_key.bin 2>/dev/null
    echo -n "$IV" | tr '_-' '/+' | base64 -d > ${KBS_WORK_DIR}/iv.bin 2>/dev/null
    echo -n "$CIPHERTEXT" | tr '_-' '/+' | base64 -d > ${KBS_WORK_DIR}/ciphertext.bin 2>/dev/null
    echo -n "$TAG" | tr '_-' '/+' | base64 -d > ${KBS_WORK_DIR}/tag.bin 2>/dev/null

    # Decrypt AES key using RSA-OAEP-256
    rlLog "Decrypting AES key with RSA-OAEP-256..."
    if openssl pkeyutl -decrypt -inkey keys/tee_private.pem \
        -pkeyopt rsa_padding_mode:oaep \
        -pkeyopt rsa_oaep_md:sha256 \
        -pkeyopt rsa_mgf1_md:sha256 \
        -in ${KBS_WORK_DIR}/encrypted_key.bin -out ${KBS_WORK_DIR}/aes_key.bin 2>&1; then

        rlLog "AES key length: $(wc -c < ${KBS_WORK_DIR}/aes_key.bin) bytes"
        rlLog "Ciphertext length: $(wc -c < ${KBS_WORK_DIR}/ciphertext.bin) bytes"

        # Decrypt using Python cryptography (openssl enc doesn't support AES-GCM)
        rlLog "Decrypting secret with AES-256-GCM..."
        DECRYPTED=$(python3 << PYEOF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

with open('${KBS_WORK_DIR}/aes_key.bin', 'rb') as f:
    key = f.read()
with open('${KBS_WORK_DIR}/iv.bin', 'rb') as f:
    nonce = f.read()
with open('${KBS_WORK_DIR}/ciphertext.bin', 'rb') as f:
    ciphertext = f.read()
with open('${KBS_WORK_DIR}/tag.bin', 'rb') as f:
    tag = f.read()
with open('${KBS_WORK_DIR}/protected.txt', 'rb') as f:
    aad = f.read()

aesgcm = AESGCM(key)
plaintext = aesgcm.decrypt(nonce, ciphertext + tag, aad)
print(plaintext.decode('utf-8'), end='')
PYEOF
        )
        rlLog "Decrypted secret: '$DECRYPTED'"
        rlLog "Expected secret:  '$TEST_SECRET'"

        if [[ "$DECRYPTED" == "$TEST_SECRET" ]]; then
            rlPass "Decrypted secret matches expected value"
        else
            rlFail "Decrypted secret does not match! Got '$DECRYPTED', expected '$TEST_SECRET'"
        fi
    else
        rlLog "RSA-OAEP decryption failed"
        rlFail "Could not decrypt AES key"
    fi
}

rlJournalStart

    rlPhaseStartSetup "Configure and start KBS"
        rlRun 'rlImport "./test-helpers"' || rlDie "cannot import trustee-tests/test-helpers library"
        rlAssertRpm trustee-kbs

        # Create directories
        rlRun "mkdir -p ${KBS_REPO_DIR}"
        rlRun "mkdir -p ${KBS_WORK_DIR}"
        rlRun "mkdir -p keys"

        # Write RSA key for decryption
        echo "$RSA_PRIVATE_KEY" > keys/tee_private.pem

        # Generate HTTPS certs if needed
        if [[ "$HTTP_MODE" == "https" ]]; then
            trusteeGenerateHTTPCerts
            HTTP_SERVER_CONFIG="insecure_http = false
sockets = [\"${SERVER_IP}:${KBS_PORT}\"]
private_key = \"${PWD}/HttpsCerts/host.key\"
certificate = \"${PWD}/HttpsCerts/host.crt\""
        else
            HTTP_SERVER_CONFIG="insecure_http = true
sockets = [\"${SERVER_IP}:${KBS_PORT}\"]"
        fi

        # Create JWK file for token verification (uses hardcoded Ed25519 X value)
        cat > ${KBS_REPO_DIR}/trusted_jwk.json << EOF
{
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "${ED25519_X}",
            "alg": "EdDSA",
            "use": "sig",
            "kid": "test-key-1"
        }
    ]
}
EOF
        rlLog "Created JWK file for token verification"
        rlRun "cat ${KBS_REPO_DIR}/trusted_jwk.json"
        # Create a dummy Ed25519 public key for admin config (not used but required)
        cat > keys/admin_public.pem << 'KEYEOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEASHiAhbAmKH5cy00kGGux0YGtDWKs9nEizs3Br8FZUuY=
-----END PUBLIC KEY-----
KEYEOF

        # Create KBS config
        cat > ${KBS_CONFIG} << EOF
[http_server]
${HTTP_SERVER_CONFIG}

[admin]
auth_public_key = "${PWD}/keys/admin_public.pem"

[attestation_token]
insecure_key = true
trusted_jwk_sets = ["file://${KBS_REPO_DIR}/trusted_jwk.json"]

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "${KBS_REPO_DIR}"
EOF
        rlLog "Created KBS config"
        rlRun "cat ${KBS_CONFIG}"

        # Start KBS server
        rlRun "/usr/bin/kbs --config-file ${KBS_CONFIG} &> kbs.log &"
        KBS_PID=$!
        rlRun "sleep 3"
        rlAssertExists "/proc/${KBS_PID}" "KBS server should be running"
        rlLog "KBS started with PID ${KBS_PID}"
        TEST_SECRET="my-super-secret-key-12345"
        rlRun "mkdir -p ${KBS_REPO_DIR}/default/keys"
        rlRun "echo -n '${TEST_SECRET}' > ${KBS_REPO_DIR}/default/keys/test-secret"
        rlAssertExists "${KBS_REPO_DIR}/default/keys/test-secret"
        rlLog "Pre-populated secret in KBS repository"
    rlPhaseEnd

    rlPhaseStartTest "Access resource with pre-signed JWT token"
        rlLog "Using static pre-signed token (${#STATIC_TOKEN} chars)"
        rlRun -s "curl -s ${CURL_OPTS} -w '\nHTTP_CODE:%{http_code}' \
            -H 'Authorization: Bearer ${STATIC_TOKEN}' \
            ${HTTP_MODE}://localhost:${KBS_PORT}/kbs/v0/resource/default/keys/test-secret" 0 "Access resource with token"

        HTTP_CODE=$(tail -1 $rlRun_LOG | grep -o '[0-9]*')
        rlLog "HTTP response code: ${HTTP_CODE}"

        if [[ "${HTTP_CODE}" == "200" ]]; then
            RESPONSE=$(head -n -1 $rlRun_LOG)
            kbsDecryptResources "$RESPONSE"
        elif [[ "${HTTP_CODE}" == "401" ]]; then
            rlFail "Token not accepted (HTTP 401)"
            cat $rlRun_LOG
            rlLog "=== KBS log ==="
            tail -20 kbs.log
        else
            rlFail "Unexpected response code: ${HTTP_CODE}"
            cat $rlRun_LOG
        fi
    rlPhaseEnd

    rlPhaseStartTest "Access resource without token (should fail)"
        rlRun -s "curl -s ${CURL_OPTS} -w '\nHTTP_CODE:%{http_code}' \
            ${HTTP_MODE}://localhost:${KBS_PORT}/kbs/v0/resource/default/keys/test-secret" 0 "Access without token"

        HTTP_CODE=$(tail -1 $rlRun_LOG | grep -o '[0-9]*')
        if [[ "${HTTP_CODE}" == "401" ]]; then
            rlPass "Correctly rejected request without token (HTTP 401)"
        else
            rlFail "Expected 401, got ${HTTP_CODE}"
        fi
    rlPhaseEnd

    rlPhaseStartCleanup "Tear down KBS and clean up files"
        # Show KBS logs only if test failed
        if ! rlGetTestState; then
            rlLog "=== KBS Server Log (showing due to test failure) ==="
            cat kbs.log || true
        fi

        if [[ -n "${KBS_PID}" ]] && [[ -d "/proc/${KBS_PID}" ]]; then
            rlRun "kill ${KBS_PID}" 0 "Stop KBS server"
        fi
        rlRun "pkill -f '/usr/bin/kbs' || true"

        rlRun "rm -rf ${KBS_WORK_DIR}"
        rlRun "rm -rf keys"
        rlRun "rm -f ${KBS_CONFIG} kbs.log"
        if [[ "$HTTP_MODE" == "https" ]]; then
            rlRun "rm -rf HttpsCerts"
        fi
    rlPhaseEnd

rlJournalEnd
