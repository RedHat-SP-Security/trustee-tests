#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
. /usr/share/beakerlib/beakerlib.sh || exit 1

HTTP_MODE="${HTTP_MODE:-http}"
KBS_IMAGE="${KBS_IMAGE:-${TRUSTEE_GUEST_COMPONENTS_KBS_IMAGE:-}}"
KBS_CONTAINER="trustee-guest-components-config-test"

TEST_RESOURCE_PATH="default/keys/guest-components-config-test"
TEST_RESOURCE_URI="kbs:///${TEST_RESOURCE_PATH}"
TEST_SECRET="guest-components-config-test-secret"

rlJournalStart

    rlPhaseStartSetup "Start KBS for trustee-attester configuration tests"
        rlRun 'rlImport "./test-helpers"' || rlDie "cannot import trustee-tests/test-helpers library"
        rlRun "TEST_TMP_DIR=\$(mktemp -d)" 0 "Create test temporary directory"

        rlAssertRpm trustee-guest-components
        rlRun "command -v trustee-attester" 0 "trustee-attester must be installed"
        trusteeSelectCompatibility
        trusteeAssertGuestComponentsVersion
        rlRun "TRUSTEE_GUEST_COMPONENTS_VERSION=\$(rpm -q --qf '%{VERSION}' trustee-guest-components)" \
            0 "Get trustee-guest-components version"
        trusteeRequireKbsImage "${KBS_IMAGE}"
        TEST_RESOURCE_URI=$(trusteeResourceUri "${TEST_RESOURCE_PATH}")
        TEST_RESOURCE_FILE=$(trusteeResourceFile "${TEST_RESOURCE_PATH}")
        rlLog "Using KBS image ${KBS_IMAGE} with trustee-guest-components ${TRUSTEE_GUEST_COMPONENTS_VERSION}."

        if [[ "${HTTP_MODE}" == "https" ]]; then
            HTTPS_CERTS="--cert-file ${PWD}/HttpsCerts/host.crt"
            trusteeGenerateHTTPCerts
        fi

        trusteeGenerateTeeKey
        trusteeCreateKbsConfig "${HTTP_MODE}"

        rlRun "mkdir -p '${TRUSTEE_KBS_POLICY_DIR}' '${TRUSTEE_KBS_AS_WORK_DIR}/opa' \"\$(dirname '${TEST_RESOURCE_FILE}')\"" \
            0 "Create KBS policy and resource directories"
        rlRun "printf '%s\\n' 'package policy' '' 'default allow = true' > '${TRUSTEE_KBS_RESOURCE_POLICY_FILE}'" \
            0 "Write KBS resource policy"
        if [[ "${TRUSTEE_KBS_PROFILE}" == "legacy" ]]; then
            rlRun "printf '%s\\n' 'package policy' '' 'default allow = true' > '${TRUSTEE_KBS_AS_WORK_DIR}/opa/default.rego'" \
                0 "Write sample-attestation policy"
        fi
        rlRun "printf '%s' '${TEST_SECRET}' > '${TEST_RESOURCE_FILE}'" \
            0 "Provision test resource"

        trusteeStartKbsContainer "${KBS_CONTAINER}" "${KBS_IMAGE}"
    rlPhaseEnd

    rlPhaseStartTest "Valid endpoint and CA retrieve the test resource"
        rlRun "trustee-attester --url '${HTTP_MODE}://${SERVER_CN}:${SERVER_PORT}' ${HTTPS_CERTS} get-resource --path '${TEST_RESOURCE_URI}' > '${TEST_TMP_DIR}/resource.b64' 2> '${TEST_TMP_DIR}/trustee-attester.log'" \
            0 "Retrieve resource with valid configuration"
        if [[ "${TRUSTEE_KBS_PROFILE}" == "legacy" ]]; then
            rlAssertGrep "Sample Attester will be used" "${TEST_TMP_DIR}/trustee-attester.log"
        fi
        rlRun "awk 'NF { value=\$0 } END { print value }' '${TEST_TMP_DIR}/resource.b64' | base64 --decode > '${TEST_TMP_DIR}/resource'" \
            0 "Decode retrieved resource"
        retrieved_secret=$(<"${TEST_TMP_DIR}/resource")
        rlAssertEquals "Retrieved resource matches the provisioned secret" \
            "${retrieved_secret}" "${TEST_SECRET}"
    rlPhaseEnd

    rlPhaseStartTest "Invalid KBS URL is rejected"
        rlRun "trustee-attester --url 'not-a-url' get-resource --path '${TEST_RESOURCE_PATH}'" \
            1-255 "Reject malformed KBS URL"
    rlPhaseEnd

    rlPhaseStartTest "Unreachable KBS endpoint is rejected"
        rlRun "trustee-attester --url 'http://127.0.0.1:1' get-resource --path '${TEST_RESOURCE_PATH}'" \
            1-255 "Reject unreachable KBS endpoint"
    rlPhaseEnd

    if [[ "${HTTP_MODE}" == "https" ]]; then
        rlPhaseStartTest "HTTPS rejects missing and incorrect CA certificates"
            rlRun "openssl req -x509 -nodes -days 1 -newkey rsa:2048 -keyout '${TEST_TMP_DIR}/wrong-ca.key' -out '${TEST_TMP_DIR}/wrong-ca.crt' -subj '/CN=wrong-ca'" \
                0 "Create an unrelated CA certificate"

            rlRun "trustee-attester --url 'https://${SERVER_CN}:${SERVER_PORT}' get-resource --path '${TEST_RESOURCE_PATH}'" \
                1-255 "Reject HTTPS without a trusted CA"
            rlRun "trustee-attester --url 'https://${SERVER_CN}:${SERVER_PORT}' --cert-file '${TEST_TMP_DIR}/wrong-ca.crt' get-resource --path '${TEST_RESOURCE_PATH}'" \
                1-255 "Reject HTTPS with an incorrect CA"
        rlPhaseEnd
    fi

    rlPhaseStartCleanup "Stop KBS and remove test artifacts"
        if ! rlGetTestState; then
            rlLog "=== trustee-attester log (test failed) ==="
            rlRun "cat '${TEST_TMP_DIR}/trustee-attester.log'" 0,1 "Show trustee-attester log"
            rlLog "=== KBS container log (test failed) ==="
            rlRun "podman logs '${KBS_CONTAINER}'" 0,1 "Show KBS container log"
        fi

        trusteeStopKbsContainer "${KBS_CONTAINER}"
        rlRun "rm -rf '${TEST_TMP_DIR}'" 0 "Remove test temporary directory"
        rlRun "rm -f '${TEST_RESOURCE_FILE}' '${TRUSTEE_KBS_REPO_DIR}/tee_pubkey.pem'" \
            0 "Remove test resources and TEE public key"
        rlRun "rm -f '${TRUSTEE_KBS_RESOURCE_POLICY_FILE}' '${TRUSTEE_KBS_AS_WORK_DIR}/opa/default.rego'" \
            0 "Remove test policies"
        rlRun "rm -rf TeeKeys config" 0 "Remove generated keys and KBS configuration"

        if [[ "${HTTP_MODE}" == "https" ]]; then
            rlRun "rm -rf HttpsCerts" 0 "Remove generated HTTPS certificates"
        fi
    rlPhaseEnd

rlJournalEnd
