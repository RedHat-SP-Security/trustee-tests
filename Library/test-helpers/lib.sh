#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: provides basic function for token manipulation
#   Authors: Patrik Koncity <pkoncity@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2025 Red Hat, Inc.
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
#   library-prefix = trustee
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include Beaker environment
. /usr/share/beakerlib/beakerlib.sh || exit 1

true <<'=cut'
=pod

=head1 NAME

trustee-tests/test-helpers - provides shell function for trustee testing

=head1 DESCRIPTION

The library provides shell function to ease trustee test implementation.

=cut

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Variables
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# we are using hardcoded paths so they are preserved due to reboots
export __INTERNAL_trusteeTmpDir
[ -n "$__INTERNAL_trusteeTmpDir" ] || __INTERNAL_trusteeTmpDir="/var/tmp/trusteeLib"

# --- Script Variables ---
# Using localhost for both server and client
export SERVER_CN="localhost"
export SERVER_IP="127.0.0.1"
export SERVER_PORT="8080"
export TRUSTEE_DIR="trustee"
export TEST_DISK_IMG="test_disk.img"
export TEST_DISK_DEV="/dev/loop0"
# For Azure SEV-SNP VMs, this is the correct attester
export ATTESTER_TYPE="az-snp-vtpm-attester"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Functions
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteeCreateKbsConfig

Generates the kbs-config.toml file with support for HTTP or HTTPS mode.

    trusteeCreateKbsConfig MODE [SERVER_IP] [SERVER_PORT]

=over

=item MODE (required)

The server mode. Must be either http or https.

=item SERVER_IP (optional)

The IP address the KBS server will listen on. Defaults to the value of the global SERVER_IP variable.

=item SERVER_PORT (optional)

The port the KBS server will listen on. Defaults to the value of the global SERVER_PORT variable.

=back

This function creates the kbs-config.toml file in the config/ directory.

If MODE is https, it configures the server with insecure_http = false and adds paths to host.key and host.crt in the current working directory.

If MODE is http, it configures the server with insecure_http = true.

=cut


trusteeCreateKbsConfig() {
    # --- Parameter Validation ---
    if [[ "$1" != "http" && "$1" != "https" ]]; then
        rlFail "Invalid mode specified. Must be 'http' or 'https'."
        return 1
    fi

    # Use arguments if provided, otherwise fall back to global library variables.
    local mode="$1"
    local server_ip=${2:-$SERVER_IP}
    local server_port=${3:-$SERVER_PORT}

    # Now, validate that we have a value from either the argument or the global var.
    if [ -z "$server_ip" ] || [ -z "$server_port" ]; then
        rlFail "Server IP and Port must be provided as arguments or set as global variables (SERVER_IP, SERVER_PORT)."
        return 1
    fi

    local output_dir="config"
    local output_file="${output_dir}/kbs-config.toml"

    # --- Prepare Mode-Specific Settings ---
    local http_server_settings=""
    if [ "$mode" = "https" ]; then
        # Use printf for safe, multi-line string assignment.
        printf -v http_server_settings '%s\n%s\n%s' \
            "insecure_http = false" \
            "private_key = \"$(pwd)/HttpsCerts/host.key\"" \
            "certificate = \"$(pwd)/HttpsCerts/host.crt\""
    else # http mode
        http_server_settings="insecure_http = true"
    fi

    # Ensure the output directory exists
    rlRun "mkdir -p \"${output_dir}\"" 0 "Create config directory"
    rlLog "Generating KBS config file for ${mode} mode at '${output_file}'..."

    # --- Create Config File ---
    # Use a Here Document to write the file content.
    cat > "${output_file}" <<EOF
[http_server]
${http_server_settings}
sockets = ["${server_ip}:${server_port}"]

[attestation_token]
insecure_key = true
extra_teekey_paths = ["/opt/confidential-containers/kbs/repository/tee_pubkey.pem"]

[attestation_service]
type = "coco_as_builtin"
work_dir = "/opt/confidential-containers/attestation-service"
policy_engine = "opa"

[attestation_service.attestation_token_broker]
type = "Ear"
duration_min = 5

[attestation_service.rvps_config]
type = "BuiltIn"

[policy_engine]
policy_path = "/opa/confidential-containers/kbs/policy.rego"

[admin]
insecure_api = true

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
EOF

    rlLog "KBS config file created successfully."
}

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteeCreateLuksTestDisk

Creates a 1GB LUKS-encrypted disk image file for use in tests.

    trusteeCreateLuksTestDisk [DISK_IMAGE_PATH] [LOOP_DEVICE]

=over

=item DISK_IMAGE_PATH (optional)

The path for the disk image file to be created. Defaults to the value of the global TEST_DISK_IMG variable.

=item LOOP_DEVICE (optional)

The loopback device to use (e.g., /dev/loop0). Defaults to the value of the global TEST_DISK_DEV variable.

=back

The function performs the following steps:
1. Creates a 1GB file filled with zeros.
2. Attaches the file to the specified loopback device.
3. Generates a new LUKS key file named luks-key.
4. Formats the device with LUKS using the new key.
5. Temporarily opens the encrypted device to create an ext4 filesystem inside it.
6. Closes the device, leaving it in a ready-to-use encrypted state.

The function includes safety checks and will skip creation if the disk image file already exists or the loop device is already in use.

=cut

trusteeCreateLuksTestDisk() {
    # Use arguments if provided, otherwise fall back to global library variables.
    local disk_img=${1:-$TEST_DISK_IMG}
    local loop_dev=${2:-$TEST_DISK_DEV}
    local luks_key_file="luks-key"
    local luks_mapper_name="luks-disk"
    # --- Safety Checks ---
    if [ -b "$loop_dev" ] && losetup "$loop_dev" &>/dev/null; then
        rlLog "Loop device '${loop_dev}' is already in use. Skipping disk creation."
        return 0
    fi
    if [ -f "$disk_img" ]; then
        rlLog "Disk image '${disk_img}' already exists. Skipping disk creation."
        return 0
    fi
    rlLog "Creating new LUKS test disk at '${disk_img}'..."
    # 1. Create a loopback device to act as a disk
    rlRun "dd if=/dev/zero of=\"${disk_img}\" bs=1G count=1" 0 "Create disk image file"
    rlRun "losetup \"${loop_dev}\" \"${disk_img}\"" 0 "Attach image to loop device"
    rlAssertExists "${loop_dev}" "Loop device should exist"
    # 2. Create LUKS key and format the disk
    rlRun "dd bs=32 count=1 if=/dev/random > \"${luks_key_file}\"" 0 "Generate LUKS key"
    rlRun "cryptsetup --batch-mode luksFormat \"${loop_dev}\" --key-file ./${luks_key_file}" 0 "Format disk with LUKS"
    # 3. Temporarily open the new LUKS device to create a filesystem
    rlRun "cryptsetup luksOpen \"${loop_dev}\" \"${luks_mapper_name}\" --key-file ./${luks_key_file}" 0 "Open LUKS device"
    # 4. Create an ext4 filesystem inside it
    rlRun "mkfs.ext4 /dev/mapper/${luks_mapper_name}" 0 "Create ext4 filesystem"
    # 5. Close it again, leaving it ready for the test
    rlRun "cryptsetup luksClose \"${luks_mapper_name}\"" 0 "Close LUKS device"
    rlLog "LUKS test disk created successfully."
}

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteeCreateMountScript

Generates and makes executable a script to mount the LUKS test disk.

    trusteeCreateMountScript DATA_DISK_UUID

=over

=item DATA_DISK_UUID (required)

The unique UUID of the LUKS-formatted disk that needs to be mounted.

=back

This function creates a script named mount-luks-disk.sh inside the directory specified by the __INTERNAL_trusteeTmpDir variable.

The commands used inside the generated script depend on the build mode:
- The attest command always uses /usr/local/bin/kbs-client.
- The get-resource command uses trustee-attester if TRUSTEE_RPM is true, otherwise it also uses /usr/local/bin/kbs-client.

The function outputs the full path to the script so it can be executed by the caller.

=cut

trusteeCreateMountScript() {
    # --- Parameter Validation ---
    if [ -z "$1" ]; then
        rlFail "DATA_DISK_UUID must be provided as an argument."
        return 1
    fi
    local data_disk_uuid="$1"
    # Check for required global variables
    if [ -z "$HTTP_MODE" ] || [ -z "$SERVER_CN" ] || [ -z "$SERVER_PORT" ] || [ -z "$TRUSTEE_DIR" ]; then
        rlFail "Required global variables (HTTP_MODE, SERVER_CN, etc.) are not set."
        return 1
    fi
    # --- Determine which tool to use for get-resource ---
    local get_resource_tool=""
    if [ "$TRUSTEE_RPM" = "true" ]; then
        # The RPM-based build uses 'trustee-attester' specifically for get-resource.
        get_resource_tool="trustee-attester"
        rlLog "Generating mount script: attest (kbs-client), get-resource (trustee-attester)."
    else
        # The git-based build uses 'kbs-client' for everything.
        get_resource_tool="/usr/local/bin/kbs-client"
        rlLog "Generating mount script: attest (kbs-client), get-resource (kbs-client)."
    fi

    local tee_key_arg="--tee-key-file \"TeeKeys/tee_key.pem\""
    local script_path="${__INTERNAL_trusteeTmpDir}/mount-luks-disk.sh"

    rlLog "Creating LUKS mount script at '${script_path}'..."

    # --- Generate The Script ---
    # The 'attest' command is now hardcoded.
cat > "${script_path}" <<-EOF
		#!/bin/bash
		set -e
		echo "--> Finding disk with UUID ${data_disk_uuid}..."
		disk=\$(blkid | grep "${data_disk_uuid}" | awk -F ': ' '{print \$1}')
		if [ -z "\$disk" ]; then
		    echo "Error: Could not find disk with UUID ${data_disk_uuid}" >&2
		    exit 1
		fi
		echo "--> Attesting to KBS to get resource token using /usr/local/bin/kbs-client..."
		/usr/local/bin/kbs-client --url "${HTTP_MODE}://${SERVER_CN}:${SERVER_PORT}" ${HTTPS_CERTS} attest ${tee_key_arg} > /tmp/attestation_token
		echo "--> Using token to get LUKS key from KBS using ${get_resource_tool}..."
		${get_resource_tool} --url "${HTTP_MODE}://${SERVER_CN}:${SERVER_PORT}" ${HTTPS_CERTS} get-resource --path default/test/luks-key | base64 -d > /tmp/luks-key
		echo "--> Unlocking and mounting LUKS disk..."
		cryptsetup luksOpen \$disk luks-disk --key-file /tmp/luks-key
		echo "--> Cleaning up temporary key files..."
		rm -f /tmp/luks-key /tmp/attestation_token
		echo "--> Mounting filesystem..."
		mkdir -p /mnt/llm_models
		mount /dev/mapper/luks-disk /mnt/llm_models
		echo "Disk mounted successfully at /mnt/llm_models"
	EOF
    # --- Make The Script Executable ---
    rlRun "chmod +x \"${script_path}\"" 0 "Make mount script executable"
    # --- Output The Script Path ---
    echo "${script_path}"
}

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteeGenerateAdminKeys

Generates an Ed25519 private and public key pair (private.key and public.pub).

    trusteeGenerateAdminKeys [KEY_DIR]

=over

=item KEY_DIR (optional)

The directory where the key files will be saved. Defaults to config.

=back

This function first checks if private.key or public.pub already exist in the target directory. If they do, the function will skip the generation process to avoid overwriting existing keys.

=cut

trusteeGenerateAdminKeys() {
    # Set the output directory, defaulting to 'config' if not provided.
    local key_dir=${1:-"AdminKeys"}
    local private_key="${key_dir}/private.key"
    local public_key="${key_dir}/public.pub"
    # Check if either key file already exists to avoid overwriting them.
    if [ -f "$private_key" ] || [ -f "$public_key" ]; then
        rlLog "Admin keys already exist in '${key_dir}'. Skipping generation."
        return 0
    fi
    rlLog "Generating new admin keys in '${key_dir}'..."
    # Ensure the target directory exists.
    rlRun "mkdir -p \"${key_dir}\"" 0 "Create key directory"
    # 1. Generate the private key.
    rlRun "openssl genpkey -algorithm ed25519 > \"${private_key}\"" 0 "Generate private key"
    # 2. Extract the public key from the private key.
    rlRun "openssl pkey -in \"${private_key}\" -pubout -out \"${public_key}\"" 0 "Extract public key"
    rlLog "Admin key generation complete."
}

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteGenerateHTTPCerts

Generates a certificates for HTTP TLS handshake.

    trusteGenerateHTTPCerts [KEY_DIR]

=over

=item KEY_DIR (optional)

The directory where the cert files will be saved. Defaults to HttpsCerts.

=back

This function first checks if key and cert already exist in the target directory. If they do, the function will skip the generation process to avoid overwriting existing keys.

=cut

trusteeGenerateHTTPCerts() {
    # Set the output directory, defaulting to 'config' if not provided.
    local key_dir=${1:-"HttpsCerts"}
    local https_key="${key_dir}/host.key"
    local https_cert="${key_dir}/host.crt"
    rlRun "mkdir -p \"${key_dir}\"" 0 "Create key directory"
    cat <<EOF > $key_dir/host.conf
[req]
distinguished_name = req_distinguished_name
x509_extensions    = v3_ca
prompt             = no

[req_distinguished_name]
C  = CN
ST = Beijing
L  = Beijing
O  = Red Hat Inc.
OU = RHEL on Azure QE
CN = trusteeserver

[v3_ca]
subjectAltName = @alt_names

[alt_names]
DNS.1 = trusteeserver
DNS.2 = localhost
IP.1  = 127.0.0.1
IP.2  = ${SERVER_IP}
EOF
    # Check if either key file already exists to avoid overwriting them.
    if [ -f "$https_key" ] || [ -f "$https_cert" ]; then
        rlLog "Admin keys already exist in '${key_dir}'. Skipping generation."
        return 0
    fi
    # Ensure the target directory exists.
    rlRun "mkdir -p \"${key_dir}\"" 0 "Create key directory"
    rlLog "Generating new http key and cert in '${key_dir}'..."
    if [[ "${CRYPTO_ALG}" == "ML-DSA65" ]]; then
        rlRun "openssl req -x509 -nodes -days 365 -newkey mldsa65 -keyout ${https_key} -out ${https_cert} -config ${key_dir}/host.conf"
    else
        rlRun "openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${https_key} -out ${https_cert} -config ${key_dir}/host.conf"
    fi
}

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteeGenerateTeeKey

Generates a 2048-bit RSA private and public key pair (tee_key.pem and tee_pubkey.pem) and copies the public key to the KBS repository.

    trusteeGenerateTeeKey [KEY_DIR]

=over

=item KEY_DIR (optional)

The directory where the key files will be saved. Defaults to test.

=back

This function first checks if tee_key.pem or tee_pubkey.pem already exist in the source directory. If they do, the function will skip the entire process.

After successful generation, the new public key is copied to /opt/confidential-containers/kbs/repository/tee_pubkey.pem.

=cut


trusteeGenerateTeeKey() {
    # Set the output directory, defaulting to 'test' if not provided.
    local key_dir=${1:-"TeeKeys"}
    local private_key="${key_dir}/tee_key.pem"
    local public_key="${key_dir}/tee_pubkey.pem"
    # Check if either key file already exists to avoid overwriting them.
    if [ -f "$private_key" ] || [ -f "$public_key" ]; then
        rlLog "TEE keys already exist in '${key_dir}'. Skipping generation."
        return 0
    fi
    rlLog "Generating new TEE keys in '${key_dir}'..."
    # Ensure the target directory exists.
    rlRun "mkdir -p \"${key_dir}\"" 0 "Create key directory"
    # 1. Generate the 2048-bit RSA private key.
    rlRun "openssl genrsa -traditional -out \"${private_key}\" 2048" 0 "Generate TEE private key"
    # 2. Extract the public key from the private key.
    rlRun "openssl rsa -in \"${private_key}\" -pubout -out \"${public_key}\"" 0 "Extract TEE public key"
    # --- Deploy Public Key ---
    rlLog "Deploying TEE public key to KBS repository..."
    local kbs_repo_dir="/opt/confidential-containers/kbs/repository"
    rlRun "mkdir -p \"${kbs_repo_dir}\"" 0 "Ensure KBS repository directory exists"
    rlRun "cp \"${public_key}\" \"${kbs_repo_dir}/tee_pubkey.pem\"" 0 "Copy TEE public key to repository"
    rlLog "TEE key generation and deployment complete."
}

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteeGetPolicyFile

Downloads the correct allow_all.rego policy file corresponding to the currently installed KBS version.

    trusteeGetPolicyFile [POLICY_NAME]

=over

=item POLICY_NAME (optional)

Name of policy file which should be downloaded.

=back

This function takes no arguments. It determines which version of the policy file to download by checking for the kbs_commit_id receipt file in the librarys temporary directory.

- If the receipt file exists, it downloads the policy from the specific commit hash found in the file.
- If the file does not exist, it downloads the policy from the main branch.

The function intelligently skips the download if the correct version of the file already exists. It outputs the full local path to the policy file so it can be used by other commands.

=cut

trusteeGetPolicyFile() {
    local receipt_file="${__INTERNAL_trusteeTmpDir}/kbs_commit_id"
    local git_ref="main" # Default to 'main'

    # Determine which version is INSTALLED based on the receipt file
    if [ -f "$receipt_file" ]; then
        # A receipt exists, so a specific commit is installed. Use it.
        git_ref=$(<"$receipt_file")
        rlLog "Receipt file found. Will download policy for commit ${git_ref}."
    else
        rlLog "No receipt file found. Will download policy from main branch."
    fi

    # --- Download the policy file corresponding to the determined version ---
    local policy_name=${1:-"allow_all.rego"}
    local output_path="${__INTERNAL_trusteeTmpDir}/${policy_name}"

    if [ -f "$output_path" ]; then
        rlLog "Policy file '${policy_name}' for ref '${git_ref}' already exists."
    else
        local policy_url="https://raw.githubusercontent.com/confidential-containers/trustee/${git_ref}/kbs/sample_policies/${policy_name}"
        rlLog "Downloading policy file '${policy_name}' from ref '${git_ref}'..."
        rlRun "curl -L -f -o \"${output_path}\" \"${policy_url}\"" 0 "Download ${policy_name}"
        rlAssertExists "${output_path}" "Policy file should have been downloaded"
    fi

    # --- Output The Policy Path ---
    # This allows the caller to capture the path for use in other commands.
    echo "${output_path}"
}

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteeBuildAndInstallKBS

Performs an intelligent check to see if the Key Broker Service (KBS) needs to be built and installed, and does so if necessary.

    trusteeBuildAndInstallKBS [ATTESTER_TYPE]

=over

=item ATTESTER_TYPE (optional)

The attester type to use when building the admin client. Defaults to tdx.

=back

This function stores a receipt file (kbs_commit_id) inside the directory specified by the __INTERNAL_trusteeTmpDir variable to track the installed version.

The function's build logic changes based on the TRUSTEE_RPM environment variable:

=over

=item * If TRUSTEE_RPM is not true, it simply checks if /usr/local/bin/kbs-client exists. If it does, the build is skipped.

=item * If TRUSTEE_RPM is set to true, it performs a more advanced check:
    1. It determines the required server commit ID based on the version of the installed trustee-guest-components RPM.
    2. It checks the receipt file to find the currently installed commit ID.
    3. The build is only performed if the required commit does not match the installed commit.

=back

After a successful build, the function will create or update the receipt file if TRUSTEE_RPM was set to true, ensuring future checks are accurate.

=cut

trusteeBuildAndInstallKBS() {
    # The receipt file is now stored in the trustee-specific temporary directory.
    # The variable __INTERNAL_trusteeTmpDir is expected to be set by the parent script.
    local receipt_file="${__INTERNAL_trusteeTmpDir}/kbs_commit_id"
    local rebuild_needed=false
    local reason=""
    local required_commit_id=""

    # --- Intelligent Pre-flight Check ---
    if [ "$TRUSTEE_RPM" = "true" ]; then
        local attester_version
        attester_version=$(rpm -q --qf '%{VERSION}' trustee-guest-components 2>/dev/null | cut -d'^' -f1)

        if [ -z "$attester_version" ]; then
            rlFail "TRUSTEE_RPM=true but could not determine version of 'trustee-guest-components' RPM."
            return 1
        fi

        case "$attester_version" in
            "0.10.0") required_commit_id="c8ca7ca4b8123f4a8a07913161403397a9db594f" ;;
            *)
                rlFail "Unknown trustee-guest-components version '$attester_version'."
                return 1
                ;;
        esac

        local installed_commit_id=""
        [ -f "$receipt_file" ] && installed_commit_id=$(<"$receipt_file")

        if [ "$installed_commit_id" != "$required_commit_id" ]; then
            rebuild_needed=true
            reason="Required commit (\"$required_commit_id\") does not match installed commit (\"$installed_commit_id\")."
        else
            reason="Correct version (\"$required_commit_id\") is already installed."
        fi
    else
        # In non-RPM mode, we want the 'main' branch version.
        if [ ! -f "/usr/local/bin/kbs-client" ]; then
            rebuild_needed=true
            reason="KBS client not found."
        elif [ -f "$receipt_file" ]; then
            # A receipt file exists, meaning a specific commit is installed.
            # Since we now want 'main', we need to rebuild.
            rebuild_needed=true
            reason="A specific version is installed, but the main branch version is now required."
        else
            # The client exists and there's no receipt file, so 'main' is already installed.
            reason="KBS client from main branch already exists."
        fi
    fi

    if [ "$rebuild_needed" = "false" ]; then
        rlLog "Skipping KBS build: \"$reason\""
        return 0
    fi

    rlLog "Proceeding with KBS build: \"$reason\""

    local repo_url="https://github.com/confidential-containers/trustee.git"
    local trustee_dir="trustee"
    local attester_type=${1:-"az-snp-vtpm-attester"}

    if [ ! -d "$trustee_dir" ]; then
        rlRun "git clone \"${repo_url}\" \"${trustee_dir}\"" 0 "Clone Trustee repository"
    else
        rlLog "Directory '${trustee_dir}' already exists, skipping clone."
    fi

    pushd "$trustee_dir/kbs" || return 1

    if [ -n "$required_commit_id" ]; then
        rlLog "Checking out compatible server commit \"${required_commit_id}\"."
        rlRun "git fetch --all --tags"
        rlRun "git checkout \"${required_commit_id}\"" 0 "Checkout specific client commit"
    else
        rlLog "Building from the current branch."
        # If the main branch is not checked out, do so.
        # This is a safety measure in case the repo was left on a specific commit.
        rlRun "git checkout main" 0 "Switch to main branch"
        rlRun "git pull" 0 "Update main branch"
    fi

    rlRun "make background-check-kbs" 0 "Run KBS background check"
    rlRun "make install-kbs" 0 "Install KBS server"
    rlRun "make cli ATTESTER=\"${attester_type}\"" 0 "Build KBS admin client (Attester: \"${attester_type}\")"
    rlRun "make install-cli" 0 "Install KBS admin client"

    if [ -n "$required_commit_id" ]; then
        rlLog "Updating receipt file with commit ID \"${required_commit_id}\"."
        rlRun "mkdir -p \"${receipt_file%/*}\""
        rlRun "printf '%s' \"${required_commit_id}\" > \"${receipt_file}\""
    else
        if [ -f "$receipt_file" ]; then
            rlLog "Clearing old KBS commit receipt file."
            rlRun "rm -f \"${receipt_file}\""
        fi
    fi

    popd
    rlLog "Trustee KBS build and installation complete."
}

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteeInstallRust

Checks for and installs the Rust programming language using the official `rustup` installer.

    trusteeInstallRust

=over

=back

This function takes no arguments. It first checks if `rustc` is available in the system's `PATH`. If it is, the function does nothing. If not, it downloads and executes the `rustup-init` script to install Rust non-interactively.

After a successful installation, you will need to **restart your shell** or manually run `source "$HOME/.cargo/env"` for the `PATH` changes to apply to your interactive terminal session.

=cut

trusteeInstallRust() {
    # First, check if rustc is already in the PATH
    if command -v rustc &> /dev/null; then
        # If the command exists, rust is already installed.
        rlLog "Rust is already installed. Skipping."
        return 0
    fi

    # If rustc is not found, proceed with installation
    rlLog "Rust not found. Installing via rustup..."
    rlRun "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" 0 "Install Rust"

    # Source the environment file to make rustc/cargo available to the rest of *this script*
    local cargo_env_path="$HOME/.cargo/env"
    if [ -f "$cargo_env_path" ]; then
        source "$cargo_env_path"
        rlLog "Sourced Rust environment for the current script session."
    else
        rlLog "ERROR: Rust installation finished, but could not find '$cargo_env_path' to source."
        return 1
    fi

    rlLog "Rust installation complete. Please restart your shell or run 'source \"\$HOME/.cargo/env\"' for the changes to take effect in your terminal."
}

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteeInstallTDXDeps

Installs Intel SGX/TDX package dependencies required for the Trustee server.

    trusteeInstallTDXDeps URL

=over

=item URL (optional)

A custom URL for the SGX RPM repository archive (`.tgz`). If this argument is not provided, the function uses a default URL for RHEL 9.4.

=back

Return 0 if unit file exists, 1 if not.

=cut


trusteeInstallTDXDeps() {
        # Define the default URL and the expected local filename
        local default_url="https://download.01.org/intel-sgx/latest/linux-latest/distro/rhel9.4-server/sgx_rpm_local_repo.tgz"
        local repo_url=${1:-$default_url}
        local local_filename="sgx_rpm_local_repo.tgz"
        local extracted_dir="sgx_rpm_local_repo"

        # Install Intel SGX/DCAP packages (build-time dependency for Trustee server)
        # Use -o to save the file with a predictable name, and -L to follow redirects.
        rlRun "curl -L -o ${local_filename} ${repo_url}"
        rlRun "tar -xf ./${local_filename}"
        pushd ${extracted_dir}
        rlRun "dnf install -y ./*.rpm" 0 "Install SGX/TDX RPMs"
        popd
}

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteeStartKbsServer

Ensures a fresh instance of the KBS server is running as a background process.

    trusteeStartKbsServer [CONFIG_FILE]

=over

=item CONFIG_FILE (optional)

The path to the KBS configuration file (kbs-config.toml). Defaults to config/kbs-config.toml.

=back

This function first uses pgrep to check if a KBS server process is already running. If an existing process is found, it will be stopped before a new one is started to ensure a clean state.

The function then starts a new server instance. The servers output is redirected to a log file named kbs.log inside the directory specified by the __INTERNAL_trusteeTmpDir variable. The new process ID is stored in the global KBS_PID variable.

=cut

trusteeStartKbsServer() {
    # --- Check for and stop any existing server ---
    # Use pgrep to see if a KBS process is already running.
    if pgrep -f "/usr/local/bin/kbs" &>/dev/null; then
        rlLog "An existing KBS server process was found. Stopping it first..."
        trusteeStopKbsServer
    fi
    # Function arguments with defaults
    local config_file=${1:-"config/kbs-config.toml"}
    local log_file="${__INTERNAL_trusteeTmpDir}/kbs.log"
    # Check if the config file exists before trying to start
    if [ ! -f "$config_file" ]; then
        rlFail "KBS config file not found at '$config_file'."
        return 1
    fi
    rlLog "Starting KBS server... Log will be at '${log_file}'"
    # Start the KBS server, redirecting all output to the log file,
    # and run it in the background (&).
    /usr/local/bin/kbs --config-file "${config_file}" &> "${log_file}" &
    # Capture the PID of the last background command.
    # KBS_PID is intentionally global so it can be used by other functions.
    KBS_PID=$!
    # Give the server a moment to start up.
    rlRun "sleep 4" 0 "Wait for KBS to initialize"
    rlAssertExists "/proc/${KBS_PID}" "KBS server process (PID ${KBS_PID}) should be running"
    rlLog "KBS server started successfully with PID ${KBS_PID}."
}

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 trusteeStopKbsServer

Stops any running instances of the KBS server using pgrep and pkill.

    trusteeStopKbsServer

=over

=back

This function takes no arguments. It uses pgrep to search for any running KBS server processes. If any are found, it attempts to stop them gracefully before forcing them to shut down if necessary.

=cut

trusteeStopKbsServer() {
    # Use pgrep with the full binary path to safely check if the process is running.
    if pgrep -f "/usr/local/bin/kbs" &>/dev/null; then
        rlLog "Found running KBS process(es). Attempting shutdown..."

        # 1. Attempt a graceful shutdown (SIGTERM)
        pkill -f "/usr/local/bin/kbs"
        sleep 2 # Give the process time to exit cleanly

        # 2. Force shutdown (SIGKILL) if it's still running
        if pgrep -f "/usr/local/bin/kbs" &>/dev/null; then
            rlLog "KBS did not shut down gracefully. Forcing stop."
            pkill -9 -f "/usr/local/bin/kbs"
            sleep 1
        fi

        rlLog "KBS server shutdown process complete."
    else
        rlLog "No running KBS server found to stop."
    fi
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Initialization
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#   Create $__INTERNAL_trusteeTmpDir directory

mkdir -p $__INTERNAL_trusteeTmpDir

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Verification
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   This is a verification callback which will be called by
#   rlImport after sourcing the library to make sure everything is
#   all right. It makes sense to perform a basic sanity test and
#   check that all required packages are installed. The function
#   should return 0 only when the library is ready to serve.

trusteeLibraryLoaded() {

    local PACKAGES=( protobuf protobuf-compiler perl-FindBin perl-IPC-Cmd perl-File-Compare perl-File-Copy tpm2-tss-devel git make tss2-devel openssl beakerlib podman nmap jq)

    echo -e "\nInstall packages required by the library when missing."
    rpm -q "${PACKAGES[@]}" || yum -y install "${PACKAGES[@]}"

    if [ -n "$__INTERNAL_trusteeTmpDir" ]; then
        rlLogDebug "Library trustee/test-helpers loaded."
        # print trustee package versions
        echo -e "\nInstalled trustee RPMs"
        rpm -qa \*trustee\*
        return 0
    else
        rlLogError "Failed loading library trustee/test-helpers."
        return 1
    fi

}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Authors
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

true <<'=cut'
=pod

=head1 AUTHORS

=over

=item *

Patrik Koncity <pkoncity@redhat.com>

=back

=cut