#!/bin/bash
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /Functional/guest/resource-authorization
#   Description: Test allowed, missing, and denied KBS resources.
#   Author: Patrik Koncity <pkoncity@redhat.com>
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
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
. /usr/share/beakerlib/beakerlib.sh || exit 1

HTTP_MODE="${HTTP_MODE:-http}"
KBS_IMAGE="${KBS_IMAGE:-${TRUSTEE_GUEST_COMPONENTS_KBS_IMAGE:-}}"
KBS_CONTAINER="trustee-guest-components-resource-auth"
TEST_RESOURCE_PATH="default/keys/authorization-test"
TEST_RESOURCE="authorization-test-secret"
MISSING_RESOURCE_PATH="default/keys/missing-resource"

rlJournalStart
    rlPhaseStartSetup "Start KBS with sample attestation"
        rlRun 'rlImport "./test-helpers"' || rlDie "cannot import trustee-tests/test-helpers library"
        rlRun "TEST_TMP_DIR=\$(mktemp -d)" 0 "Create test temporary directory"

        rlAssertRpm trustee-guest-components
        rlRun "command -v trustee-attester" 0 "trustee-attester must be installed"
        trusteeSelectCompatibility

        # Select response expectations from the compatibility contract rather
        # than parsing the guest-components version in each test.
        case "${TRUSTEE_KBS_PROFILE}" in
            legacy)
                EXPECTED_MISSING_STATUS=401
                EXPECTED_DENIED_STATUS=401
                ;;
            v022)
                EXPECTED_MISSING_STATUS=404
                EXPECTED_DENIED_STATUS=403
                ;;
            *)
                rlDie "Unknown TRUSTEE_KBS_PROFILE '${TRUSTEE_KBS_PROFILE}'."
                ;;
        esac

        trusteeAssertGuestComponentsVersion
        trusteeRequireKbsImage "${KBS_IMAGE}"

        if [[ "${HTTP_MODE}" == "https" ]]; then
            HTTPS_CERTS="--cert-file ${PWD}/HttpsCerts/host.crt"
            trusteeGenerateHTTPCerts
        fi

        trusteeGenerateTeeKey
        trusteeCreateKbsConfig "${HTTP_MODE}"

        TEST_RESOURCE_URI=$(trusteeResourceUri "${TEST_RESOURCE_PATH}")
        TEST_RESOURCE_FILE=$(trusteeResourceFile "${TEST_RESOURCE_PATH}")
        MISSING_RESOURCE_URI=$(trusteeResourceUri "${MISSING_RESOURCE_PATH}")

        rlRun "mkdir -p \"\$(dirname '${TEST_RESOURCE_FILE}')\"" \
            0 "Create resource storage directory"
        rlRun "printf '%s' '${TEST_RESOURCE}' > '${TEST_RESOURCE_FILE}'" \
            0 "Provision authorized resource"
        rlRun "printf '%s\\n' 'package policy' '' 'default allow = true' > '${TRUSTEE_KBS_RESOURCE_POLICY_FILE}'" \
            0 "Allow resource access for positive and missing-resource checks"

        if [[ "${TRUSTEE_KBS_PROFILE}" == "legacy" ]]; then
            rlRun "printf '%s\\n' 'package policy' '' 'default allow = true' > '${TRUSTEE_KBS_AS_WORK_DIR}/opa/default.rego'" \
                0 "Allow sample attestation"
        fi

        trusteeStartKbsContainer "${KBS_CONTAINER}" "${KBS_IMAGE}"
    rlPhaseEnd

    rlPhaseStartTest "Authorized resource is retrieved"
        rlRun "trustee-attester --url '${HTTP_MODE}://${SERVER_CN}:${SERVER_PORT}' ${HTTPS_CERTS} get-resource --path '${TEST_RESOURCE_URI}' > '${TEST_TMP_DIR}/allowed.b64' 2> '${TEST_TMP_DIR}/allowed.log'" \
            0 "Retrieve authorized resource"
        rlRun "awk 'NF { value=\$0 } END { print value }' '${TEST_TMP_DIR}/allowed.b64' | base64 --decode > '${TEST_TMP_DIR}/allowed'" \
            0 "Decode authorized resource"
        retrieved_resource=$(<"${TEST_TMP_DIR}/allowed")
        rlAssertEquals "Authorized resource matches" "${retrieved_resource}" "${TEST_RESOURCE}"
    rlPhaseEnd

    rlPhaseStartTest "Missing resource is rejected"
        rlRun "trustee-attester --url '${HTTP_MODE}://${SERVER_CN}:${SERVER_PORT}' ${HTTPS_CERTS} get-resource --path '${MISSING_RESOURCE_URI}' > /dev/null 2> '${TEST_TMP_DIR}/missing.log'" \
            1-255 "Missing resource is rejected"
        rlRun "podman logs '${KBS_CONTAINER}' > '${TEST_TMP_DIR}/missing-kbs.log' 2>&1" \
            0 "Capture missing-resource KBS response"
        rlRun "grep -Fq 'GET /kbs/v0/resource/${MISSING_RESOURCE_PATH} HTTP/1.1\" ${EXPECTED_MISSING_STATUS} ' '${TEST_TMP_DIR}/missing-kbs.log'" \
            0 "KBS returns HTTP ${EXPECTED_MISSING_STATUS} for missing resource"
    rlPhaseEnd

    rlPhaseStartSetup "Switch KBS to deny-all resource policy"
        trusteeStopKbsContainer "${KBS_CONTAINER}"
        rlRun "printf '%s\\n' 'package policy' '' 'default allow = false' > '${TRUSTEE_KBS_RESOURCE_POLICY_FILE}'" \
            0 "Deny resource access"
        trusteeStartKbsContainer "${KBS_CONTAINER}" "${KBS_IMAGE}"
    rlPhaseEnd

    rlPhaseStartTest "Policy-denied resource is rejected"
        rlRun "trustee-attester --url '${HTTP_MODE}://${SERVER_CN}:${SERVER_PORT}' ${HTTPS_CERTS} get-resource --path '${TEST_RESOURCE_URI}' > /dev/null 2> '${TEST_TMP_DIR}/denied.log'" \
            1-255 "Policy-denied resource is rejected"
        rlRun "podman logs '${KBS_CONTAINER}' > '${TEST_TMP_DIR}/denied-kbs.log' 2>&1" \
            0 "Capture policy-denied KBS response"
        rlRun "grep -Fq 'GET /kbs/v0/resource/${TEST_RESOURCE_PATH} HTTP/1.1\" ${EXPECTED_DENIED_STATUS} ' '${TEST_TMP_DIR}/denied-kbs.log'" \
            0 "KBS returns HTTP ${EXPECTED_DENIED_STATUS} for denied resource"
    rlPhaseEnd

    rlPhaseStartCleanup "Stop KBS and remove test artifacts"
        if ! rlGetTestState; then
            rlLog "=== trustee-attester log (test failed) ==="
            rlRun "cat '${TEST_TMP_DIR}/allowed.log' '${TEST_TMP_DIR}/missing.log' '${TEST_TMP_DIR}/denied.log'" 0,1 "Show attester logs"
            rlLog "=== KBS container log (test failed) ==="
            rlRun "podman logs '${KBS_CONTAINER}'" 0,1 "Show KBS container log"
        fi

        trusteeStopKbsContainer "${KBS_CONTAINER}"
        rlRun "rm -rf '${TEST_TMP_DIR}'" 0 "Remove test temporary directory"
        rlRun "rm -f '${TEST_RESOURCE_FILE}' '${TRUSTEE_KBS_REPO_DIR}/tee_pubkey.pem'" \
            0 "Remove test resource and TEE public key"
        rlRun "rm -f '${TRUSTEE_KBS_RESOURCE_POLICY_FILE}' '${TRUSTEE_KBS_AS_WORK_DIR}/opa/default.rego'" \
            0 "Remove test policies"
        rlRun "rm -rf TeeKeys config" 0 "Remove generated keys and KBS configuration"

        if [[ "${HTTP_MODE}" == "https" ]]; then
            rlRun "rm -rf HttpsCerts" 0 "Remove HTTPS certificates"
        fi
    rlPhaseEnd
rlJournalEnd
