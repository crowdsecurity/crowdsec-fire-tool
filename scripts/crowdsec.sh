#!/bin/sh

# TODO: test with pre-releases / non-canonical versions

set -eu

#shellcheck disable=SC1007
THIS_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
THIS_TMP="$THIS_DIR/tmp"

CROWDSEC_GITHUB_RELEASE="github.com/crowdsecurity/crowdsec/releases/download"
CROWDSEC_VERSION="1.4.6"
CROWDSEC_FILE="crowdsec-release-static.tgz"
CROWDSEC_DEB_HASH="720fea74c397334e865f314e7b94e813bd67583a4a93416cc73d38405836f9f5"
CROWDSEC_RPM_HASH="df51f6e722c6f2bdfa542f84b636d0106f7e46b19dc0649abbe1b832f69dffa9"
CROWDSEC_TAR_HASH="e378a6d4ebe54ac95a7d9e1d084fe3eabd8f921ffff3f8b31d867486a84b723d"

FIRETOOL_VERSION="0.3"
FIRETOOL_FILE="crowdsec-fire-tool"
FIRETOOL_HASH="6c3ca50cacca73dc5db30c44c4aec5b790f593bac08fefc901bb6c2826b7ce41"

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
    rm -f "$THIS_TMP/$script_name"

    echo "${FG_CYAN}Downloading $script_url to ${THIS_TMP}${RESET}"

    download "$script_url" "$THIS_TMP"

    if [ "$distro" = "deb" ]; then
        SCRIPT_HASH="$CROWDSEC_DEB_HASH"
    else
        SCRIPT_HASH="$CROWDSEC_RPM_HASH"
    fi

    error=$(hash_check "$THIS_TMP/$script_name" "$SCRIPT_HASH")
    if [ -n "$error" ]; then
        echo "$error" >&2
        exit 1
    fi

    echo "${FG_GREEN}Script hash verified.${RESET}"

    printf '%s' "Set up the package repository? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    quit_if_no "$answer"

    echo "${FG_CYAN}Installing the repository...${RESET}"
    bash "$THIS_TMP/$script_name"

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
    if [ -z "$(hash_check "$THIS_TMP/$CROWDSEC_FILE" "$CROWDSEC_TAR_HASH")" ]; then
        echo "${FG_GREEN}$CROWDSEC_FILE already downloaded.${RESET}"
        return
    fi

    # remove a previous download
    rm -f "$THIS_TMP/$CROWDSEC_FILE"

    release_url="$CROWDSEC_GITHUB_RELEASE/v$CROWDSEC_VERSION/$CROWDSEC_FILE"

    echo "${FG_CYAN}Downloading $release_url to ${THIS_TMP}${RESET}"

    download "$release_url" "$THIS_TMP"

    error=$(hash_check "$THIS_TMP/$CROWDSEC_FILE" "$CROWDSEC_TAR_HASH")
    if [ -n "$error" ]; then
        echo "$error" >&2
        exit 1
    fi
    echo "${FG_GREEN}Archive hash verified.${RESET}"
}



install_crowdsec_from_github() {
    printf '%s' "Install CrowdSec $CROWDSEC_VERSION from the generic Linux release (tar.gz)? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    quit_if_no "$answer"

    download_crowdsec_from_github

    echo "${FG_CYAN}Extracting archive to ${THIS_TMP}${RESET}"

    rm -rf "$THIS_TMP/crowdsec-v$CROWDSEC_VERSION"

    tar -xzf "$THIS_TMP/$CROWDSEC_FILE" -C "$THIS_TMP"

    printf '%s' "Install CrowdSec now? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    quit_if_no "$answer"

    cd "$THIS_TMP/crowdsec-v$CROWDSEC_VERSION" || (echo "${ERROR}Cannot cd to $THIS_TMP/crowdsec-v${CROWDSEC_VERSION}${RESET}" && exit 1)

    echo "${FG_CYAN}Running wizard.sh...${RESET}"

    ./wizard.sh --install
}


download_fire_tool() {
    if [ -z "$(hash_check "/usr/local/bin/$FIRETOOL_FILE" "$FIRETOOL_HASH")" ]; then
        echo "${FG_GREEN}crowdsec-fire-tool already installed.${RESET}"
        return
    fi

    echo "${FG_CYAN}Installing crowdsec-fire-tool.${RESET}"

    # remove a previous download
    rm -f "$THIS_TMP/$FIRETOOL_FILE"

    release_url="https://github.com/crowdsecurity/crowdsec-fire-tool/releases/download/v$FIRETOOL_VERSION/$FIRETOOL_FILE"

    echo "${FG_CYAN}Downloading $release_url to ${THIS_TMP}${RESET}"

    download "$release_url" "$THIS_TMP"

    error=$(hash_check "$THIS_TMP/$FIRETOOL_FILE" "$FIRETOOL_HASH")
    if [ -n "$error" ]; then
        echo "$error" >&2
        exit 1
    fi

    echo "${FG_GREEN}File hash verified.${RESET}"

    echo "${FG_CYAN}Installing crowdsec-fire-tool to /usr/local/bin...${RESET}"

    mv "$THIS_TMP/$FIRETOOL_FILE" /usr/local/bin
    chown root:root /usr/local/bin/"$FIRETOOL_FILE"
    chmod 755 /usr/local/bin/"$FIRETOOL_FILE"

    echo "${FG_GREEN}done.${RESET}"
}


download_yq() {
    if [ -z "$(hash_check "$THIS_TMP/$YQ_FILE" "$YQ_HASH")" ]; then
        echo "${FG_GREEN}mikefarah/yq already installed.${RESET}"
        return
    fi

    echo "${FG_CYAN}Installing mikefarah/yq.${RESET}"

    # remove a previous download
    rm -f "$THIS_TMP/$YQ_FILE"

    release_url="https://github.com/mikefarah/yq/releases/download/v$YQ_VERSION/$YQ_FILE"

    echo "${FG_CYAN}Downloading $release_url to ${THIS_TMP}${RESET}"

    download "$release_url" "$THIS_TMP"

    error=$(hash_check "$THIS_TMP/$YQ_FILE" "$YQ_HASH")
    if [ -n "$error" ]; then
        echo "$error" >&2
        exit 1
    fi

    echo "${FG_GREEN}File hash verified.${RESET}"

    chmod +x "$THIS_TMP/$YQ_FILE"
    ln -sf "$YQ_FILE" "$THIS_TMP/yq"
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
    if [ -s "$ETC_CROWDSEC/fire.yaml" ]; then
        cti_key="$("$THIS_TMP/yq" e '.cti_key' "$ETC_CROWDSEC/fire.yaml")"
        if [ -n "$cti_key" ]; then
            echo "${FG_GREEN}CTI key already configured.${RESET}"
            return
        fi
    fi

    printf '%s' "Enter your CTI key: "
    read -r answer

    touch "$ETC_CROWDSEC/fire.yaml"
    chmod 0600 "$ETC_CROWDSEC/fire.yaml"
    cti_key="$answer" "$THIS_TMP/yq" e '.cti_key = strenv(cti_key)' --inplace "$ETC_CROWDSEC/fire.yaml"
}

download_fire_db() {
    printf '%s' "Download or update fire.txt? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    case $answer in
        n* | N*)
            return
            ;;
    esac

    datadir="$("$THIS_TMP/yq" e '.config_paths.data_dir' "$ETC_CROWDSEC/config.yaml" | sed 's:/*$::')"

    echo "${FG_CYAN}Data directory is set to $datadir.${RESET}"

    echo "${FG_CYAN}Downloading $datadir/fire.txt...${RESET}"
    "/usr/local/bin/$FIRETOOL_FILE" --config /etc/crowdsec/fire.yaml --output "$datadir/fire.txt"
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
    cron_file="$THIS_TMP/crowdsec-fire-tool.cron"
    if [ ! -s "$cron_file" ]; then
        echo "${FG_CYAN}Generating $cron_file...${RESET}"
        cat <<-EOT > "$cron_file"
		0 */4 * * * root /usr/local/bin/crowdsec-fire-tool --config /etc/crowdsec/fire.yaml --output /var/lib/crowdsec/data/fire.txt && systemctl reload crowdsec

		EOT
    fi
    if [ ! -s /etc/cron.d/crowdsec-fire-tool ]; then
        printf '%s' "Do you want to install the cron job? [${FG_GREEN}Y${RESET}/n] "
        read -r answer

        case $answer in
            n* | N*)
                return
                ;;
        esac

        echo "${FG_CYAN}Installing $cron_file...${RESET}"
        install -m 0644 "$cron_file" /etc/cron.d/crowdsec-fire-tool
        echo "${FG_GREEN}done.${RESET}"
    fi
}

confirm_file_configuration() {
    mkdir -p "$ETC_CROWDSEC/acquis.d"

    printf '%s' "Do you want to generate the file configurations? [${FG_GREEN}Y${RESET}/n] "
    read -r confirm
    case $confirm in
        n* | N*)
            return
            ;;
    esac
    generate_file_configuration
}

generate_file_configuration() {
    printf '%s' "Enter the path to the directory containing the files: "
    read -r directory
    if [ -z "$directory" ]; then
        return
    fi
    if [ ! -d "$directory" ]; then
        echo "${ERROR}Directory does not exist.${RESET}"
        # XXX: Recursion
        generate_file_configuration
    fi
    for file in $(find "$directory" -type f); do
        if [ -f "$file" ]; then
            if file --mime-type "$file" | grep -q text; then
                printf '%s' "Do you want to add $file to the configuration? [y/${FG_RED}N${RESET}] "
                read -r answer

                case $answer in
                    y* | Y*)
                        fname=${file##*/}
                        if [ -f "$ETC_CROWDSEC/acquis.d/$fname.yaml" ]; then
                            echo "${FG_GREEN}$fname already exists.${RESET}"
                            echo "You can update it manually from $ETC_CROWDSEC/acquis.d/$fname.yaml"
                            continue
                        fi

                        printf '%s' "Enter the type of the file (apache2, nginx, etc.): "
                        read -r answer
                        if [ -z "$answer" ]; then
                            echo "${ERROR}Type cannot be empty. skipping file.${RESET}"
                            continue
                        fi

                        echo "${FG_CYAN}Adding $file to the configuration...${RESET}"

                        cat <<-EOT > "$ETC_CROWDSEC/acquis.d/$fname.yaml"
			filename: $file
			labels:
			  type: $answer
			EOT
                        ;;
                esac
                continue
            fi
        fi
    done
    generate_file_configuration
}

enroll_instance_to_app() {
	printf '%s' "Do you want to enroll to https://app.crowdsec.net? [${FG_GREEN}Y${RESET}/n] "
	read -r answer

	case $answer in
		n* | N*)
			return
			;;
	esac

	printf '%s' "Enter your enrollment token: "
	read -r token

	echo "${FG_CYAN}Enrolling to https://app.crowdsec.net...${RESET}"
	cscli console enroll "$token"

	echo "${FG_GREEN}Please accept the enrollment on https://app.crowdsec.net${RESET}"
}

install_all_collections() {
    printf '%s' "Do you want to install all collections? [${FG_GREEN}Y${RESET}/n] "
    read -r answer

    case $answer in
        n* | N*)
            return
            ;;
    esac

    echo "${FG_CYAN}Installing all collections...${RESET}"
    #shellcheck disable=SC2046
    cscli collections install --ignore $(cscli collections list -a -oraw | cut -d, -f1 | grep -v ^name$)
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
        crowdsec -dsn "file://$("$THIS_TMP/yq" e '.filename' "$file")" -type "$("$THIS_TMP/yq" e '.labels.type' "$file")" -no-api 2>&1 | grep "performed"
        continue
    done
}

start_crowdsec_service() {
    if systemctl is-active --quiet crowdsec; then
        echo "${FG_CYAN}Starting crowdsec...${RESET}"
        systemctl start crowdsec
    fi
}

restart_crowdsec_service() {
    if systemctl is-active --quiet crowdsec; then
        echo "${FG_CYAN}Restarting crowdsec...${RESET}"
        systemctl restart crowdsec
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

if [ ! -d "$THIS_TMP" ]; then
    echo "${FG_CYAN}Creating $THIS_TMP...${RESET}"
    mkdir -p "$THIS_TMP"
fi

case $action in
    install)
        download_yq
        download_fire_tool
        install_crowdsec
        ;;
    configure)
        configure_database
        install_all_collections
	enroll_instance_to_app
        update_fire_db
        configure_scenario
        generate_cron_job
        confirm_file_configuration
        restart_crowdsec_service
        ;;
    run)
        case $1 in
            coldlog)
                cold_log_mode
                ;;
        esac
        ;;
esac
