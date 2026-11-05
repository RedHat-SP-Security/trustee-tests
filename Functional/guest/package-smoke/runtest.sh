#!/bin/bash
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /Functional/guest/package-smoke
#   Description: Verify the trustee-guest-components RPM contract.
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

rlJournalStart
    rlPhaseStartSetup "Verify trustee-guest-components package"
        rlRun 'rlImport "./test-helpers"' || rlDie "cannot import trustee-tests/test-helpers library"
        rlAssertRpm trustee-guest-components
        trusteeSelectCompatibility
        trusteeAssertGuestComponentsVersion
    rlPhaseEnd

    rlPhaseStartTest "Test installed trustee-attester CLI"
        rlRun "rpm -V trustee-guest-components" 0 "Verify installed package files"
        rlRun "test -x /usr/bin/trustee-attester" 0 "trustee-attester is executable"
        if [[ "${TRUSTEE_KBS_PROFILE}" == "v022" ]]; then
            rlRun "trustee-attester --version" 0 "trustee-attester reports its version"
        else
            rlLog "Skipping trustee-attester --version: legacy client does not support it"
        fi
        rlRun "trustee-attester --help" 0 "trustee-attester provides help"
        rlRun "trustee-attester --url" 1-255 "Missing URL value is rejected"
        rlRun "trustee-attester --url http://127.0.0.1:8080" 1-255 "Missing subcommand is rejected"
        rlRun "trustee-attester --url not-a-url get-resource --path default/keys/test" \
            1-255 "Malformed URL is rejected"
    rlPhaseEnd
rlJournalEnd
