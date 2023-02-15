#!/bin/sh

# TODO: test with pre-releases / non-canonical versions

set -eu

#shellcheck disable=SC1007
THIS_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMPDIR="$THIS_DIR/tmp"

CROWDSEC_GITHUB_RELEASE="github.com/crowdsecurity/crowdsec/releases/download"
CROWDSEC_VERSION="1.4.6"
CROWDSEC_FILE="crowdsec-release-static.tgz"
CROWDSEC_DEB_HASH="720fea74c397334e865f314e7b94e813bd67583a4a93416cc73d38405836f9f5"
CROWDSEC_RPM_HASH="df51f6e722c6f2bdfa542f84b636d0106f7e46b19dc0649abbe1b832f69dffa9"
CROWDSEC_TAR_HASH="e378a6d4ebe54ac95a7d9e1d084fe3eabd8f921ffff3f8b31d867486a84b723d"

FIRETOOL_VERSION="0.2"
FIRETOOL_FILE="crowdsec-fire-tool"
FIRETOOL_HASH="79f801ec105c10c772151ecd5b947beb28b4848cee6f59f09ac2a4593adbad06"

YQ_VERSION="4.30.8"
YQ_FILE="yq_linux_amd64"
YQ_HASH="6c911103e0dcc54e2ba07e767d2d62bcfc77452b39ebaee45b1c46f062f4fd26"

ETC_CROWDSEC="/etc/crowdsec"

# ------------------------------------------------------------------------------
# General helpers
# ------------------------------------------------------------------------------

usage() {
    echo "Usage: $0 [install|configure|run]"
}

set_colors() {
    FG_BLACK=""
    FG_RED=""
    FG_GREEN=""
    FG_YELLOW=""
    FG_BLUE=""
    FG_MAGENTA=""
    FG_CYAN=""
    FG_WHITE=""
    BOLD=""
    RESET=""

    #shellcheck disable=SC2034
    if tput sgr0 >/dev/null; then
        FG_BLACK=$(tput setaf 0)
        FG_RED=$(tput setaf 1)
        FG_GREEN=$(tput setaf 2)
        FG_YELLOW=$(tput setaf 3)
        FG_BLUE=$(tput setaf 4)
        FG_MAGENTA=$(tput setaf 5)
        FG_CYAN=$(tput setaf 6)
        FG_WHITE=$(tput setaf 7)
        BOLD=$(tput bold)
        RESET=$(tput sgr0)
    fi

    WARNING="$FG_YELLOW"
    ERROR="$FG_RED"
}

detect_distro() {
    if [ -f /etc/debian_version ]; then
        echo "deb"
    elif [ -f /etc/redhat-release ]; then
        echo "rpm"
    else
        echo "${ERROR}Unsupported distribution.${RESET}"
        exit 1
    fi
}

amiroot() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "${WARNING}This script must be run as root.${RESET}"
        exit 1
    fi
}

echo_separator() {
    echo "----------------------"
}

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

# uses curl or wget depending on what is available
download() {
    if [ -z "$1" ]; then
        echo "${ERROR}download() requires a URL as first argument${RESET}"
        exit 1
    fi
    if [ -z "$2" ]; then
        echo "${ERROR}download() requires a destination directory as second argument${RESET}"
        exit 1
    fi
    if [ ! -d "$2" ]; then
        echo "${ERROR}$2 is not a directory${RESET}"
        exit 1
    fi

    if command -v curl >/dev/null; then
        cd "$2" || (echo "${ERROR}Could not cd to $2${RESET}" && exit 1)
        # older versions of curl don't support --output-dir
        curl -sSLO --fail --remote-name "$1"
        cd - >/dev/null
    elif command -v wget >/dev/null; then
        wget -nv -P "$2" "$1"
    else
        echo "${ERROR}Neither curl nor wget is available, cannot download files.${RESET}"
        exit 1
    fi
}

quit_if_no() {
    case $1 in
        n* | N*)
            echo "${ERROR}CrowdSec installation interrupted.${RESET}"
            exit 1
            ;;
    esac
}

# verify the hash of a downloaded file
hash_check() {
    if [ -z "$1" ]; then
        echo "${ERROR}hash_check() requires a file as first argument${RESET}"
        exit 1
    fi
    if [ -z "$2" ]; then
        echo "${ERROR}hash_check() requires a hash as second argument${RESET}"
        exit 1
    fi
    if [ ! -f "$1" ]; then
        echo "${ERROR}$1 is not a file${RESET}"
        exit 1
    fi
    hash=$(sha256sum "$1" | cut -d ' ' -f 1)
    if [ "$hash" != "$2" ]; then
        echo "${ERROR}The sha256 hash of $1 does not match the expected value.${RESET}"
        echo "Expected: $2"
        echo "Got: $hash"
        echo "${WARNING}This could be normal (the file may have changed), but could also be a man-in-the-middle attempt.${RESET}"
        echo "${WARNING}Do not use the downloaded file, but check with CrowdSec for a new version of $(basename "$0").${RESET}"
    fi
}

check_apt_success() {
    if apt show crowdsec 2>/dev/null | grep -q "Version: $CROWDSEC_VERSION"; then
        echo "${FG_GREEN}CrowdSec ${CROWDSEC_VERSION} installed successfully.${RESET}"
    else
        echo "${ERROR}CrowdSec installation failed.${RESET}"
        exit 1
    fi
}

check_dnf_success() {
    if dnf list installed crowdsec 2>/dev/null | grep -q "crowdsec.$CROWDSEC_VERSION"; then
        echo "${FG_GREEN}CrowdSec $CROWDSEC_VERSION installed successfully.${RESET}"
    else
        echo "${ERROR}CrowdSec installation failed.${RESET}"
        exit 1
    fi
}

install_crowdsec_from_repo() {
    distro=$(detect_distro)

    echo "${FG_CYAN}Installing CrowdSec $CROWDSEC_VERSION for a ${distro}-based distribution.${RESET}"

    script_name="script.${distro}.sh"

    script_url="https://packagecloud.io/install/repositories/crowdsec/crowdsec/${script_name}"

    # remove a previous download
    rm -f "$TMPDIR/$script_name"

    echo "${FG_CYAN}Downloading $script_url to ${TMPDIR}${RESET}"

    download "$script_url" "$TMPDIR"

    if [ "$distro" = "deb" ]; then
        SCRIPT_HASH="$CROWDSEC_DEB_HASH"
    else
        SCRIPT_HASH="$CROWDSEC_RPM_HASH"
    fi

    error=$(hash_check "$TMPDIR/$script_name" "$SCRIPT_HASH")
    if [ -n "$error" ]; then
        echo "$error" >&2
        exit 1
    fi

    echo "${FG_GREEN}Script hash verified.${RESET}"

    printf '%s' "Set up the package repository? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    quit_if_no "$answer"

    echo "${FG_CYAN}Installing the repository...${RESET}"
    bash "$TMPDIR/$script_name"

    printf '%s' "Install CrowdSec now? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    quit_if_no "$answer"

    if [ "$distro" = "deb" ]; then
        apt-get update
        apt-get install -y "crowdsec=$CROWDSEC_VERSION"
        check_apt_success
    elif [ "$distro" = "rpm" ]; then
        dnf install -y "crowdsec-$CROWDSEC_VERSION"
        check_dnf_success
    fi
}

download_crowdsec_from_github() {
    if [ -z "$(hash_check "$TMPDIR/$CROWDSEC_FILE" "$CROWDSEC_TAR_HASH")" ]; then
        echo "${FG_GREEN}$CROWDSEC_FILE already downloaded.${RESET}"
        return
    fi

    # remove a previous download
    rm -f "$TMPDIR/$CROWDSEC_FILE"

    release_url="$CROWDSEC_GITHUB_RELEASE/v$CROWDSEC_VERSION/$CROWDSEC_FILE"

    echo "${FG_CYAN}Downloading $release_url to ${TMPDIR}${RESET}"

    download "$release_url" "$TMPDIR"

    hash_check "$TMPDIR/$CROWDSEC_FILE" "$CROWDSEC_TAR_HASH"
    echo "${FG_GREEN}Archive hash verified.${RESET}"
}



install_crowdsec_from_github() {
    printf '%s' "Install CrowdSec $CROWDSEC_VERSION from the generic Linux release (tar.gz)? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    quit_if_no "$answer"

    download_crowdsec_from_github

    echo "${FG_CYAN}Extracting archive to ${TMPDIR}${RESET}"

    rm -rf "$TMPDIR/crowdsec-v$CROWDSEC_VERSION"

    tar -xzf "$TMPDIR/$CROWDSEC_FILE" -C "$TMPDIR"

    printf '%s' "Install CrowdSec now? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    quit_if_no "$answer"

    cd "$TMPDIR/crowdsec-v$CROWDSEC_VERSION" || (echo "${ERROR}Cannot cd to $TMPDIR/crowdsec-v${CROWDSEC_VERSION}${RESET}" && exit 1)

    echo "${FG_CYAN}Running wizard.sh...${RESET}"

    ./wizard.sh --install
}


download_fire_tool() {
    if [ -z "$(hash_check "$TMPDIR/$FIRETOOL_FILE" "$FIRETOOL_HASH")" ]; then
        echo "${FG_GREEN}crowdsec-fire-tool already installed.${RESET}"
        return
    fi

    echo "${FG_CYAN}Installing crowdsec-fire-tool.${RESET}"

    # remove a previous download
    rm -f "$TMPDIR/$FIRETOOL_FILE"

    release_url="https://github.com/crowdsecurity/crowdsec-fire-tool/releases/download/v$FIRETOOL_VERSION/$FIRETOOL_FILE"

    echo "${FG_CYAN}Downloading $release_url to ${TMPDIR}${RESET}"

    download "$release_url" "$TMPDIR"

    hash_check "$TMPDIR/$FIRETOOL_FILE" "$FIRETOOL_HASH"
    echo "${FG_GREEN}File hash verified.${RESET}"

    chmod +x "$TMPDIR/$FIRETOOL_FILE"
}


download_yq() {
    if [ -z "$(hash_check "$TMPDIR/$YQ_FILE" "$YQ_HASH")" ]; then
        echo "${FG_GREEN}mikefarah/yq already installed.${RESET}"
        return
    fi

    echo "${FG_CYAN}Installing mikefarah/yq.${RESET}"

    # remove a previous download
    rm -f "$TMPDIR/$YQ_FILE"

    release_url="https://github.com/mikefarah/yq/releases/download/v$YQ_VERSION/$YQ_FILE"

    echo "${FG_CYAN}Downloading $release_url to ${TMPDIR}${RESET}"

    download "$release_url" "$TMPDIR"

    error=$(hash_check "$TMPDIR/$YQ_FILE" "$YQ_HASH")
    if [ -n "$error" ]; then
        echo "$error" >&2
        exit 1
    fi

    echo "${FG_GREEN}File hash verified.${RESET}"

    chmod +x "$TMPDIR/$YQ_FILE"
    ln -sf "$YQ_FILE" "$TMPDIR/yq"
}


install_crowdsec() {
    amiroot

    echo_separator

    printf '%s' "Do you want to install CrowdSec from the official repository (packagecloud.io)? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    if [ "$answer" = "n" ] || [ "$answer" = "N" ]; then
        install_crowdsec_from_github
    else
        install_crowdsec_from_repo
    fi
}

# ------------------------------------------------------------------------------
# Configure
# ------------------------------------------------------------------------------

configure_cti_key() {
    if [ -s "$ETC_CROWDSEC/cti-key" ]; then
        echo "${FG_GREEN}CTI key already configured.${RESET}"
        return
    fi

    printf '%s' "Enter your CTI key: "
    read -r answer

    echo "$answer" | install -m 0600 /dev/fd/0 "$ETC_CROWDSEC/cti-key"
}

download_fire_db() {
    printf '%s' "Download or update fire.txt? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    case $answer in
        n* | N*)
            return
            ;;
    esac

    datadir="$("$TMPDIR/yq" e '.config_paths.data_dir' "$ETC_CROWDSEC/config.yaml" | sed 's:/*$::')"

    echo "${FG_CYAN}Data directory is set to $datadir.${RESET}"

    echo "${FG_CYAN}Downloading $datadir/fire.txt...${RESET}"
    CTI_API_KEY=$(cat "$ETC_CROWDSEC/cti-key") "$TMPDIR/$FIRETOOL_FILE" > "$datadir/fire.txt"
    echo "${FG_GREEN}done.${RESET}"
}


update_fire_db() {
    configure_cti_key
    download_fire_db
}

configure_database() {
    echo "${FG_CYAN}Updating config.yaml.local...${RESET}"
    cat <<-EOT > "$ETC_CROWDSEC/config.yaml.local"
	db_config:
	  use_wal: true
	  flush:
	    max_items: 200000
	    max_age: 14d
	EOT
}

configure_scenario() {
    echo "${FG_CYAN}Configuring scenario...${RESET}"
    cat <<-EOT > "$ETC_CROWDSEC/scenarios/fire.yaml"
	type: trigger
	name: crowdsecurity/fire
	description: Crowdsecurity fire database
	filter: evt.Meta.source_ip in File('fire.txt')
	groupby: evt.Meta.source_ip
	blackhole: 2m
	data:
	  - dest_file: 'fire.txt'
	    type: string
	labels:
	  remediation: true
	EOT
}

generate_cron_job() {
	cron_file="$TMPDIR/crowdsec-fire-tool.cron"
    if [ ! -s "$cron_file" ]; then
        echo "${FG_CYAN}Generating $cron_file...${RESET}"
		cat <<-EOT > "$cron_file"
	0 */2 * * * root CTI_API_KEY=\$(cat /etc/crowdsec/cti-key) $TMPDIR/crowdsec-fire-tool > /var/lib/crowdsec/data/fire.txt

	EOT
    else
        echo "${FG_GREEN}$cron_file already exists.${RESET}"
        echo "You can update it manually from $cron_file"
	fi

    printf '%s' "Do you want to install the cron job? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    case $answer in
        n* | N*)
            return
            ;;
    esac

    echo "${FG_CYAN}Installing $cron_file...${RESET}"
    install -m 0644 "$cron_file" /etc/cron.d/crowdsec-fire-tool
}

generate_file_configuration() {
    mkdir -p "$ETC_CROWDSEC/acquis.d"

    printf '%s' "Do you want to generate the file configurations? [${FG_GREEN}Y${RESET}/n] "
    read -r confirm
    case $confirm in
        n* | N*)
            return
            ;;
    esac
    printf '%s' "Enter the path to the directory containing the files: "
    read -r directory
    for file in $(find "$directory" -type f); do
        if [ -f "$file" ]; then
            if file --mime-type "$file" | grep -q text; then
                printf '%s' "Do you want to add $file to the configuration? [${FG_GREEN}Y${RESET}/n] "
                read -r answer

                case $answer in
                    n* | N*)
                        continue
                        ;;
                esac

                printf '%s' "Enter the type of the file (apache2, nginx, etc.): "
                read -r answer
                if [ -z "$answer" ]; then
                    echo "${ERROR}Type cannot be empty. skipping file.${RESET}"
                    continue
                fi
                fname=${file##*/}
                if [ -f "$ETC_CROWDSEC/acquis.d/$fname.yaml" ]; then
                    echo "${FG_GREEN}$fname already exists.${RESET}"
                    echo "You can update it manually from $ETC_CROWDSEC/acquis.d/$fname.yaml"
                    continue
                fi
                
                echo "${FG_CYAN}Adding $fname to the configuration...${RESET}"

                cat <<-EOT > "$ETC_CROWDSEC/acquis.d/$fname.yaml"
                    filename: $file
                    labels:
                      type: $answer
					EOT
            fi
        fi
    done
}

# ------------------------------------------------------------------------------
# Run
# ------------------------------------------------------------------------------

cold_log_mode() {
    for file in $(find "$ETC_CROWDSEC/acquis.d" -type f); do
        printf '%s' "Do you want to process $file? [${FG_GREEN}Y${RESET}/n] "
        read -r answer

        case $answer in
            n* | N*)
                continue
                ;;
        esac

        echo "${FG_CYAN}Processing $file...${RESET}"
        crowdsec -dsn "file://$("$TMPDIR/yq" e '.filename' $file)" -type "$("$TMPDIR/yq" e '.labels.type' $file)" -no-api 2>&1 | grep "performed"
        continue
    done
}

start_crowdsec_service() {
    if systemctl is-active --quiet crowdsec; then
        echo "${FG_CYAN}Starting crowdsec...${RESET}"
        systemctl start crowdsec
    fi
}
# ------------------------------------------------------------------------------

set_colors

if [ $# -lt 1 ]; then
    usage
    exit 1
fi

action="$1"
shift

case $action in
    install | configure | run)
        ;;
    *)
        echo "${ERROR}Unknown action: $action${RESET}"
        usage
        exit 1
        ;;
esac

# in case we're running from outside the directory
cd "$THIS_DIR" || (echo "${ERROR}Cannot cd to $THIS_DIR${RESET}" && exit 1)

if [ ! -d "$TMPDIR" ]; then
    echo "${FG_CYAN}Creating $TMPDIR...${RESET}"
    mkdir -p "$TMPDIR"
fi

case $action in
    install)
        download_yq
        download_fire_tool
        install_crowdsec
        ;;
    configure)
        update_fire_db
        configure_scenario
        configure_database
        generate_cron_job
        generate_file_configuration
        ;;
    run)
        case $1 in
            coldlog)
                cold_log_mode
                ;;
        esac
        ;;
esac
