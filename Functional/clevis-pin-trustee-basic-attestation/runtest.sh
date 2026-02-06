#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /Functional/clevis-pin-trustee-basic-attestation
#   Description: Basic attestation of clevis-pin-trustee
#   Author: Adam Prikryl <aprikryl@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2026 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
. /usr/share/beakerlib/beakerlib.sh || exit 1

# Minimal functional test for clevis-pin-trustee.
#
# Tests the clevis encrypt/decrypt round-trip against a KBS server
# using mock attestation. On non-TEE hardware, trustee-attester
# auto-falls back to the sample attester. KBS with allow_all.rego
# policy accepts sample attestation evidence.
#
# KBS runs in a container because the RPM-packaged binary
# (trustee-kbs) is compiled without the coco-as-builtin feature.
# The RCAR auth endpoint requires this feature; without it, KBS
# returns PluginNotFound for POST /kbs/v0/auth. The container
# image is built with coco-as-builtin support.
#
# The container image is pinned to a specific version because
# the RCAR protocol version must match exactly between client
# and server (strict =X.Y.Z check). The trustee-guest-components
# RPM uses protocol 0.2.0; :latest uses 0.4.0 (incompatible).
#
# Chain:
#   clevis encrypt trustee '<config>'
#     -> clevis-pin-trustee encrypt
#       -> trustee-attester --url <url> get-resource --path <path>
#         -> RCAR: POST /kbs/v0/auth + POST /kbs/v0/attest
#         -> GET /kbs/v0/resource/<path> (returns JWE)
#         -> decrypts JWE internally, outputs base64(key)
#       -> parses key as {"key_type":"oct","key":"<hex>"}
#       -> encrypts plaintext with JWE (Dir + A256GCM)
#   clevis decrypt (same fetch flow, then decrypts JWE)

# Should be set in main.fmf
HTTP_MODE="${HTTP_MODE:-http}"

# Test key in the format clevis-pin-trustee expects.
TEST_KEY_JSON='{"key_type":"oct","key":"2b442dd5db4478367729ef8bbf2e7480"}'
TEST_KEY_PATH="default/keys/clevis-test-key"
TEST_PLAINTEXT="Hello from clevis-pin-trustee minimal test"

# KBS filesystem paths (must match kbs-config.toml created by trusteeCreateKbsConfig)
KBS_REPO_DIR="/opt/confidential-containers/kbs/repository"
KBS_POLICY_DIR="/opa/confidential-containers/kbs"
AS_WORK_DIR="/opt/confidential-containers/attestation-service"

# KBS container settings
# The image must match the RCAR protocol version used by the RPM trustee-attester.
# The trustee-guest-components RPM sends RCAR protocol 0.2.0.
# The :latest tag uses protocol 0.4.0 (incompatible). This commit is from
# the v0.13.0 era (May 2025) which uses protocol 0.2.0.
KBS_IMAGE="${KBS_IMAGE:-ghcr.io/confidential-containers/staged-images/kbs:a150bcccf847361593a53df0e044ddbc07914ced}"
KBS_CONTAINER="kbs-clevis-test"

rlJournalStart

    rlPhaseStartSetup "Configure and start KBS for mock attestation"
        rlRun 'rlImport "./test-helpers"' || rlDie "cannot import trustee-tests/test-helpers library"

        # Check prerequisites
        rlAssertRpm clevis
        rlAssertRpm clevis-pin-trustee
        rlRun "which trustee-attester" 0 "trustee-attester must be available"
        rlRun "which podman" 0 "podman must be available"

        # Set up HTTPS if needed
        if [[ "$HTTP_MODE" == "https" ]]; then
            HTTPS_CERTS="--cert-file ${PWD}/HttpsCerts/host.crt"
            trusteeGenerateHTTPCerts
        fi

        # Generate admin keys (Ed25519, for KBS admin API authentication)
        trusteeGenerateAdminKeys

        # Generate TEE key pair (RSA, public key deployed to KBS repository)
        trusteeGenerateTeeKey

        # Create KBS config (insecure_key=true, coco_as_builtin AS)
        trusteeCreateKbsConfig "${HTTP_MODE}"

        # ---- Place resources and policy in filesystem ----

        # 1. KBS resource access policy (allow_all)
        rlRun "mkdir -p ${KBS_POLICY_DIR}" 0 "Create KBS policy directory"
        cat > "${KBS_POLICY_DIR}/policy.rego" << 'POLICYEOF'
package policy

default allow = true
POLICYEOF
        rlAssertExists "${KBS_POLICY_DIR}/policy.rego" "KBS resource policy file"

        # 2. Attestation service policy (allow_all for sample attester evidence)
        rlRun "mkdir -p ${AS_WORK_DIR}/opa" 0 "Create AS OPA policy directory"
        cat > "${AS_WORK_DIR}/opa/default.rego" << 'ASPOLICYEOF'
package policy

default allow = true
ASPOLICYEOF
        rlAssertExists "${AS_WORK_DIR}/opa/default.rego" "AS attestation policy file"

        # 3. Test key resource in KBS repository
        RESOURCE_FILE="${KBS_REPO_DIR}/${TEST_KEY_PATH}"
        RESOURCE_DIR=$(dirname "${RESOURCE_FILE}")
        rlRun "mkdir -p ${RESOURCE_DIR}" 0 "Create resource directory"
        echo -n "${TEST_KEY_JSON}" > "${RESOURCE_FILE}"
        rlAssertExists "${RESOURCE_FILE}" "Test key resource file"

        # ---- Start KBS in container ----
        # The RPM binary (trustee-kbs) lacks the coco-as-builtin feature,
        # so RCAR attestation (POST /kbs/v0/auth) fails with PluginNotFound.
        # The container image is built with coco-as-builtin support.
        rlRun "podman pull ${KBS_IMAGE}" 0 "Pull KBS container image"

        # Build volume mount list
        PODMAN_VOLUMES="-v $(pwd)/config/kbs-config.toml:$(pwd)/config/kbs-config.toml:Z"
        PODMAN_VOLUMES+=" -v ${KBS_REPO_DIR}:${KBS_REPO_DIR}:Z"
        PODMAN_VOLUMES+=" -v ${KBS_POLICY_DIR}:${KBS_POLICY_DIR}:Z"
        PODMAN_VOLUMES+=" -v ${AS_WORK_DIR}:${AS_WORK_DIR}:Z"
        if [[ "$HTTP_MODE" == "https" ]]; then
            PODMAN_VOLUMES+=" -v $(pwd)/HttpsCerts:$(pwd)/HttpsCerts:Z"
        fi

        rlRun "podman run -d --replace --name ${KBS_CONTAINER} --network host \
            ${PODMAN_VOLUMES} \
            ${KBS_IMAGE} \
            /usr/local/bin/kbs --config-file $(pwd)/config/kbs-config.toml" \
            0 "Start KBS container"

        rlRun "sleep 4" 0 "Wait for KBS to initialize"

        # Verify the container is running
        if ! podman ps --filter "name=${KBS_CONTAINER}" --filter "status=running" --format '{{.Names}}' | grep -q "${KBS_CONTAINER}"; then
            rlFail "KBS container is not running"
            rlLog "=== KBS container log ==="
            podman logs "${KBS_CONTAINER}" 2>&1
            rlDie "KBS failed to start"
        fi
        rlPass "KBS container is running"
        rlLog "=== KBS startup log ==="
        podman logs "${KBS_CONTAINER}" 2>&1 | head -10
    rlPhaseEnd

    # ==================================================================
    #   TEST 1: clevis encrypt + decrypt round-trip
    # ==================================================================
    rlPhaseStartTest "clevis encrypt/decrypt round-trip with trustee pin"
        # Build the clevis trustee pin config JSON.
        # The "cert" field must contain the PEM certificate CONTENT, not a file path.
        # clevis-pin-trustee writes this value to a temp file and passes it to
        # trustee-attester --cert-file.
        if [[ "$HTTP_MODE" == "https" ]]; then
            CERT_VALUE=$(awk '{printf "%s\\n", $0}' "${PWD}/HttpsCerts/host.crt")
        else
            CERT_VALUE=""
        fi

        CLEVIS_CONFIG="{\"servers\":[{\"url\":\"${HTTP_MODE}://${SERVER_CN}:${SERVER_PORT}\",\"cert\":\"${CERT_VALUE}\"}],\"path\":\"${TEST_KEY_PATH}\"}"
        rlLog "Clevis trustee config: ${CLEVIS_CONFIG}"

        # Encrypt
        rlLog "Encrypting test plaintext with clevis pin trustee..."
        echo -n "${TEST_PLAINTEXT}" | clevis encrypt trustee "${CLEVIS_CONFIG}" \
            > "${__INTERNAL_trusteeTmpDir}/encrypted.jwe" \
            2> "${__INTERNAL_trusteeTmpDir}/encrypt.log"
        ENCRYPT_RC=$?

        if [[ ${ENCRYPT_RC} -ne 0 ]]; then
            rlFail "clevis encrypt trustee failed (exit code ${ENCRYPT_RC})"
            rlLog "=== clevis encrypt stderr ==="
            cat "${__INTERNAL_trusteeTmpDir}/encrypt.log"
            rlLog "=== KBS log (last 50 lines) ==="
            podman logs "${KBS_CONTAINER}" 2>&1 | tail -50
        else
            rlPass "clevis encrypt trustee succeeded"
            JWE_SIZE=$(wc -c < "${__INTERNAL_trusteeTmpDir}/encrypted.jwe")
            rlLog "Encrypted JWE size: ${JWE_SIZE} bytes"

            # Decrypt
            rlLog "Decrypting with clevis decrypt..."
            DECRYPTED=$(clevis decrypt \
                < "${__INTERNAL_trusteeTmpDir}/encrypted.jwe" \
                2> "${__INTERNAL_trusteeTmpDir}/decrypt.log")
            DECRYPT_RC=$?

            if [[ ${DECRYPT_RC} -ne 0 ]]; then
                rlFail "clevis decrypt failed (exit code ${DECRYPT_RC})"
                rlLog "=== clevis decrypt stderr ==="
                cat "${__INTERNAL_trusteeTmpDir}/decrypt.log"
                rlLog "=== KBS log (last 50 lines) ==="
                podman logs "${KBS_CONTAINER}" 2>&1 | tail -50
            else
                rlLog "Decrypted: '${DECRYPTED}'"
                rlLog "Expected:  '${TEST_PLAINTEXT}'"
                if [[ "${DECRYPTED}" == "${TEST_PLAINTEXT}" ]]; then
                    rlPass "Round-trip successful: decrypted plaintext matches original"
                else
                    rlFail "Plaintext mismatch: got '${DECRYPTED}', expected '${TEST_PLAINTEXT}'"
                fi
            fi
        fi
    rlPhaseEnd

    # ==================================================================
    #   TEST 2: clevis decrypt must fail when KBS is unreachable
    # ==================================================================
    rlPhaseStartTest "clevis decrypt fails when KBS is stopped"
        if [[ -s "${__INTERNAL_trusteeTmpDir}/encrypted.jwe" ]]; then
            # Stop KBS container
            rlRun "podman stop ${KBS_CONTAINER}" 0 "Stop KBS container"

            clevis decrypt \
                < "${__INTERNAL_trusteeTmpDir}/encrypted.jwe" \
                > /dev/null \
                2> "${__INTERNAL_trusteeTmpDir}/decrypt_noserver.log"
            DECRYPT_RC=$?

            if [[ ${DECRYPT_RC} -ne 0 ]]; then
                rlPass "clevis decrypt correctly failed without KBS (exit code ${DECRYPT_RC})"
            else
                rlFail "clevis decrypt should have failed without running KBS"
            fi

            # Restart KBS container for cleanup phase
            rlRun "podman start ${KBS_CONTAINER}" 0 "Restart KBS container"
            rlRun "sleep 2"
        else
            rlLog "Skipping: no encrypted blob from Test 1"
        fi
    rlPhaseEnd

    # ==================================================================
    #   CLEANUP
    # ==================================================================
    rlPhaseStartCleanup "Tear down KBS and clean up"
        # Show KBS log on test failure
        if ! rlGetTestState; then
            rlLog "=== KBS Container Log (showing due to test failure) ==="
            podman logs "${KBS_CONTAINER}" 2>&1
        fi

        rlRun "podman stop ${KBS_CONTAINER} 2>/dev/null || true" 0,1 "Stop KBS container"
        rlRun "podman rm -f ${KBS_CONTAINER} 2>/dev/null || true" 0,1 "Remove KBS container"

        rlRun "rm -f ${__INTERNAL_trusteeTmpDir}/encrypted.jwe"
        rlRun "rm -f ${__INTERNAL_trusteeTmpDir}/encrypt.log"
        rlRun "rm -f ${__INTERNAL_trusteeTmpDir}/decrypt.log"
        rlRun "rm -f ${__INTERNAL_trusteeTmpDir}/decrypt_noserver.log"
        rlRun "rm -rf AdminKeys"
        rlRun "rm -rf TeeKeys"
        rlRun "rm -rf config"
        # Clean up filesystem artifacts
        rlRun "rm -f ${KBS_POLICY_DIR}/policy.rego"
        rlRun "rm -f ${AS_WORK_DIR}/opa/default.rego"
        rlRun "rm -f ${KBS_REPO_DIR}/${TEST_KEY_PATH}"
        if [[ "$HTTP_MODE" == "https" ]]; then
            rlRun "rm -rf HttpsCerts"
        fi
    rlPhaseEnd

rlJournalEnd
