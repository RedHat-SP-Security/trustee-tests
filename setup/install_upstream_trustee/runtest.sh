#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
. /usr/share/beakerlib/beakerlib.sh || exit 1

# should be set in plan
#TRUSTEE_RPM="true"

rlJournalStart

    rlPhaseStartTest "Install trustee and its dependencies"
        rlRun 'rlImport "./test-helpers"' || rlDie "cannot import trustee-tests/test-helpers library"
        # Install rust
        trusteeInstallRust
        trusteeInstallTDXDeps
        trusteeBuildAndInstallKBS
    rlPhaseEnd

    rlPhaseStartTest "Test installed binaries"
        rlRun "/usr/local/bin/kbs-client --help"
    rlPhaseEnd

rlJournalEnd
