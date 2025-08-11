#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
. /usr/share/beakerlib/beakerlib.sh || exit 1

# Should be set in main.fmf
#HTTP_MODE="https"

rlJournalStart

    rlPhaseStartSetup "Configure and start Trustee KBS on localhost"
        rlRun 'rlImport "./test-helpers"' || rlDie "cannot import trustee-tests/test-helpers library"
        if [[ "$HTTP_MODE" == "https" ]]; then
            HTTPS_CERTS="--cert-file ${PWD}/HttpsCerts/host.crt"
            trusteeGenerateHTTPCerts
        fi
        # Generate admin keys
        trusteeGenerateAdminKeys
        trusteeGenerateTeeKey
        trusteeCreateKbsConfig $HTTP_MODE
        trusteeStartKbsServer
        rlRun "sleep 5"
        trusteeGetPolicyFile "allow_all.rego"
        rlRun "/usr/local/bin/kbs-client --url ${HTTP_MODE}://${SERVER_CN}:${SERVER_PORT} ${HTTPS_CERTS} config --auth-private-key AdminKeys/private.key set-resource-policy --policy-file ${__INTERNAL_trusteeTmpDir}/allow_all.rego"
    rlPhaseEnd

    # =================================================================
    #   TEST PHASE
    # =================================================================
    rlPhaseStartTest "Test 1: Create and mount an encrypted LUKS disk"
        trusteeCreateLuksTestDisk
        # Push the luks-key to the KBS server using the admin kbs-client
        rlRun "/usr/local/bin/kbs-client --url $HTTP_MODE://${SERVER_CN}:${SERVER_PORT} ${HTTPS_CERTS} config --auth-private-key AdminKeys/private.key set-resource --resource-file ./luks-key --path default/test/luks-key"
        # Create the auto-mount script using the official trustee-attester
        DATA_DISK_UUID=$(blkid -s UUID -o value ${TEST_DISK_DEV})
        # Create the auto-mount script using the kbs-client
        trusteeCreateMountScript "$DATA_DISK_UUID"
        rlRun "${__INTERNAL_trusteeTmpDir}/mount-luks-disk.sh"
        rlRun -s "lsblk"
        rlAssertGrep 'crypt /mnt/llm_models' $rlRun_LOG
    rlPhaseEnd

    # =================================================================
    #   CLEANUP PHASE
    # =================================================================
    rlPhaseStartCleanup "Tear down Trustee and test environment"
        # 1. stop KBS server
        rlRun "trusteeStopKbsServer"
        # 2. Cleanup LUKS disk
        rlRun "umount /mnt/llm_models || true"
        rlRun "cryptsetup luksClose luks-disk || true"
        rlRun "losetup -d ${TEST_DISK_DEV} || true"
        rlRun "rm -f ${TEST_DISK_IMG} luks-key"
        # 3. Remove scripts and configs
        rlRun "rm -f ${__INTERNAL_trusteeTmpDir}/mount-luks-disk.sh"
        rlRun "rm -rf ${__INTERNAL_trusteeTmpDir}/allow_all.rego"
        rlRun "rm -rf AdminKeys"
        rlRun "rm -rf TeeKeys"
        rlRun "rm -rf ${TRUSTEE_DIR}"
        rlRun "rm -rf sgx_rpm_local_repo sgx_rpm_local_repo.tgz"
        if [[ "$HTTP_MODE" == "https" ]]; then
            rlRun "rm -rf HttpsCerts"
        fi
    rlPhaseEnd

rlJournalEnd