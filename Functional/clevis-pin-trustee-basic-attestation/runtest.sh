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
RESTRICTED_KEY_JSON='{"key_type":"oct","key":"9a3f7c1e5b824d6f0a1e3c5b7d9f2a4c"}'
RESTRICTED_KEY_PATH="default/keys/restricted-key"
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

        # Create a test-local temporary directory
        rlRun "TMP_DIR=\$(mktemp -d)" 0 "Create test temporary directory"

        # Check prerequisites
        rlAssertRpm clevis
        rlAssertRpm clevis-pin-trustee
        rlRun "which trustee-attester" 0 "trustee-attester must be available"
        rlRun "which podman" 0 "podman must be available"

        # Set up HTTPS if needed
        if [[ "$HTTP_MODE" == "https" ]]; then
            HTTPS_CERTS="--cert-file ${PWD}/HttpsCerts/host.crt"
            trusteeGenerateHTTPCerts
            CERT_VALUE=$(awk '{printf "%s\\n", $0}' "${PWD}/HttpsCerts/host.crt")
        else
            CERT_VALUE=""
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
        rlRun "printf '%s\n' 'package policy' '' 'default allow = true' > '${KBS_POLICY_DIR}/policy.rego'" \
            0 "Write KBS resource access policy"
        rlAssertExists "${KBS_POLICY_DIR}/policy.rego" "KBS resource policy file"

        # 2. Attestation service policy (allow_all for sample attester evidence)
        rlRun "mkdir -p ${AS_WORK_DIR}/opa" 0 "Create AS OPA policy directory"
        rlRun "printf '%s\n' 'package policy' '' 'default allow = true' > '${AS_WORK_DIR}/opa/default.rego'" \
            0 "Write AS attestation policy"
        rlAssertExists "${AS_WORK_DIR}/opa/default.rego" "AS attestation policy file"

        # 3. Test key resources in KBS repository
        RESOURCE_FILE="${KBS_REPO_DIR}/${TEST_KEY_PATH}"
        RESOURCE_DIR=$(dirname "${RESOURCE_FILE}")
        rlRun "mkdir -p ${RESOURCE_DIR}" 0 "Create resource directory"
        rlRun "echo -n '${TEST_KEY_JSON}' > '${RESOURCE_FILE}'" 0 "Write test key resource"
        rlAssertExists "${RESOURCE_FILE}" "Test key resource file"

        # 4. Restricted key resource (stored but denied by restrictive policy in Test 2)
        RESTRICTED_FILE="${KBS_REPO_DIR}/${RESTRICTED_KEY_PATH}"
        rlRun "echo -n '${RESTRICTED_KEY_JSON}' > '${RESTRICTED_FILE}'" 0 "Write restricted key resource"
        rlAssertExists "${RESTRICTED_FILE}" "Restricted key resource file"

        # ---- Start KBS in container ----
        # The RPM binary (trustee-kbs) lacks the coco-as-builtin feature,
        # so RCAR attestation (POST /kbs/v0/auth) fails with PluginNotFound.
        # The container image is built with coco-as-builtin support.
        trusteeStartKbsContainer "${KBS_CONTAINER}" "${KBS_IMAGE}"
    rlPhaseEnd

    # ==================================================================
    #   TEST 1: clevis encrypt + decrypt round-trip
    # ==================================================================
    rlPhaseStartTest "clevis encrypt/decrypt round-trip with trustee pin"
        # Build the clevis trustee pin config JSON.
        # The "cert" field must contain the PEM certificate CONTENT, not a file path.
        # clevis-pin-trustee writes this value to a temp file and passes it to
        # trustee-attester --cert-file.
        CLEVIS_CONFIG="{\"servers\":[{\"url\":\"${HTTP_MODE}://${SERVER_CN}:${SERVER_PORT}\",\"cert\":\"${CERT_VALUE}\"}],\"path\":\"${TEST_KEY_PATH}\"}"
        rlLog "Clevis trustee config: ${CLEVIS_CONFIG}"

        # Encrypt
        rlRun 'echo -n "${TEST_PLAINTEXT}" | clevis encrypt trustee "${CLEVIS_CONFIG}" > "${TMP_DIR}/encrypted.jwe" 2> "${TMP_DIR}/encrypt.log"' 0 "clevis encrypt trustee"

        # Decrypt
        rlRun 'clevis decrypt < "${TMP_DIR}/encrypted.jwe" > "${TMP_DIR}/decrypted.txt" 2> "${TMP_DIR}/decrypt.log"' 0 "clevis decrypt"

        DECRYPTED=$(<"${TMP_DIR}/decrypted.txt")
        rlAssertEquals "Decrypted plaintext matches original" "${DECRYPTED}" "${TEST_PLAINTEXT}"
    rlPhaseEnd

    # ==================================================================
    #   TEST 2: restrictive resource policy
    # ==================================================================
    rlPhaseStartTest "Restrictive policy allows only authorized key"
        # Overwrite resource policy with a restrictive one (no container restart).
        # KBS re-evaluates OPA policy from disk on each resource request.
        # In KBS v0.13.0, the resource path is in data["resource-path"]
        rlRun "printf '%s\n' 'package policy' '' 'default allow = false' '' 'allow {' '    endswith(data[\"resource-path\"], \"default/keys/clevis-test-key\")' '}' > '${KBS_POLICY_DIR}/policy.rego'" \
            0 "Write restrictive resource policy"

        # Encrypt/decrypt with allowed key should succeed
        CLEVIS_CONFIG_ALLOWED="{\"servers\":[{\"url\":\"${HTTP_MODE}://${SERVER_CN}:${SERVER_PORT}\",\"cert\":\"${CERT_VALUE}\"}],\"path\":\"${TEST_KEY_PATH}\"}"
        rlRun 'echo -n "${TEST_PLAINTEXT}" | clevis encrypt trustee "${CLEVIS_CONFIG_ALLOWED}" > "${TMP_DIR}/encrypted_allowed.jwe" 2> "${TMP_DIR}/encrypt_allowed.log"' 0 "clevis encrypt with allowed key succeeds"
        rlRun 'clevis decrypt < "${TMP_DIR}/encrypted_allowed.jwe" > "${TMP_DIR}/decrypted_allowed.txt" 2> "${TMP_DIR}/decrypt_allowed.log"' 0 "clevis decrypt with allowed key succeeds"
        DECRYPTED_ALLOWED=$(<"${TMP_DIR}/decrypted_allowed.txt")
        rlAssertEquals "Decrypted plaintext matches original (restrictive policy)" "${DECRYPTED_ALLOWED}" "${TEST_PLAINTEXT}"

        # Encrypt with restricted key should fail (policy denies access)
        CLEVIS_CONFIG_RESTRICTED="{\"servers\":[{\"url\":\"${HTTP_MODE}://${SERVER_CN}:${SERVER_PORT}\",\"cert\":\"${CERT_VALUE}\"}],\"path\":\"${RESTRICTED_KEY_PATH}\"}"
        rlRun 'echo -n "${TEST_PLAINTEXT}" | clevis encrypt trustee "${CLEVIS_CONFIG_RESTRICTED}" > "${TMP_DIR}/encrypted_restricted.jwe" 2> "${TMP_DIR}/encrypt_restricted.log"' 1-255 "clevis encrypt with restricted key denied by policy"
    rlPhaseEnd

    # ==================================================================
    #   TEST 3: clevis decrypt must fail when KBS is unreachable
    # ==================================================================
    rlPhaseStartTest "clevis decrypt fails when KBS is stopped"
        if [[ -s "${TMP_DIR}/encrypted.jwe" ]]; then
            # Stop KBS container (stays stopped through cleanup)
            rlRun "podman stop ${KBS_CONTAINER}" 0 "Stop KBS container"

            rlRun 'clevis decrypt < "${TMP_DIR}/encrypted.jwe" > /dev/null 2> "${TMP_DIR}/decrypt_noserver.log"' 1-255 "clevis decrypt fails without KBS"
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
            rlRun "podman logs ${KBS_CONTAINER}" 0,1 "Show KBS container log"
        fi

        trusteeStopKbsContainer "${KBS_CONTAINER}"

        rlRun "rm -rf ${TMP_DIR}" 0 "Remove test temporary directory"
        rlRun "rm -rf AdminKeys"
        rlRun "rm -rf TeeKeys"
        rlRun "rm -rf config"
        # Clean up filesystem artifacts
        rlRun "rm -f ${KBS_POLICY_DIR}/policy.rego"
        rlRun "rm -f ${AS_WORK_DIR}/opa/default.rego"
        rlRun "rm -f ${KBS_REPO_DIR}/${TEST_KEY_PATH}"
        rlRun "rm -f ${KBS_REPO_DIR}/${RESTRICTED_KEY_PATH}"
        if [[ "$HTTP_MODE" == "https" ]]; then
            rlRun "rm -rf HttpsCerts"
        fi
    rlPhaseEnd

rlJournalEnd
