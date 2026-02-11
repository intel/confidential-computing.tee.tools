#!/bin/bash

# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

cleanup() {
    rm -f /tmp/tdx-guest-*.log &> /dev/null
    rm -f /tmp/tdx-demo-*-monitor.sock &> /dev/null

    PID_TD=$(cat /tmp/tdx-demo-td-pid.pid 2> /dev/null)

    if [[ ! -z "$PID_TD" ]]; then
        echo "Cleanup, kill TD with PID: ${PID_TD}"
        kill -TERM ${PID_TD} &> /dev/null
    fi
    sleep 3
}

cleanup

process_args() {
    # Check for help flag first
    for arg in "$@"; do
        if [[ "$arg" == "-h" ]]; then
            usage
            exit 0
        fi
    done

    while getopts ":ho:t:u:l:m:i:k:" option; do
        case "$option" in
            o) OVMF_PATH=$OPTARG;;
            t) TD_IMG_PATH=$OPTARG;;
            u) UUID_PART_ROOTFS=$OPTARG;;
            l) LABEL_DEV_ROOTFS_DEC=$OPTARG;;
            m) TD_BOOT_MODE=$OPTARG;;
            i) INITRD_PATH=$OPTARG;;
            k) KERNEL_PATH=$OPTARG;;
            h)
                usage
                exit 0
                ;;
            :)
                echo "Error: Missing Value for option: $OPTARG"
                usage
                exit 1
                ;;
            *)
                echo "Invalid option '-$OPTARG'"
                usage
                exit 1
                ;;
        esac
    done
}

usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...

Required Options:
    -u <UUID_PART_ROOTFS>     LUKS UUID of the encrypted partition
    -l <LABEL_DEV_ROOTFS_DEC> Label for the decrypted device mapper
    -m <TD_BOOT_MODE>         Boot mode: GET_QUOTE or TD_FDE_BOOT
    -t <TD_IMG_PATH>          Path to TD guest image
    -i <INITRD_PATH>          Path to initrd image file
    -k <KERNEL_PATH>          Path to kernel (vmlinuz) image file
    -o <OVMF_PATH>            Virtual Firmware device file for TD

    -h                        Show this help
EOM
}

# Check for missing values and required options
validate_options() {
    # Check if any value starts with '-' (another option used as value)
    local options=("o:OVMF_PATH" "t:TD_IMG_PATH" "u:UUID_PART_ROOTFS" "l:LABEL_DEV_ROOTFS_DEC" "m:TD_BOOT_MODE" "i:INITRD_PATH" "k:KERNEL_PATH")

    for opt_pair in "${options[@]}"; do
        IFS=':' read -r opt_flag opt_name <<< "$opt_pair"
        local opt_value="${!opt_name}"
        if [[ "$opt_value" == -* ]]; then
            echo "Error: Missing Value for option: $opt_flag"
            usage
            exit 1
        fi
    done

    # Check if all required options were provided
    local missing_opts=()

    [[ -z "${OVMF_PATH}" ]] && missing_opts+=("-o OVMF_PATH")
    [[ -z "${TD_IMG_PATH}" ]] && missing_opts+=("-t TD_IMG_PATH")
    [[ -z "${UUID_PART_ROOTFS}" ]] && missing_opts+=("-u UUID_PART_ROOTFS")
    [[ -z "${LABEL_DEV_ROOTFS_DEC}" ]] && missing_opts+=("-l LABEL_DEV_ROOTFS_DEC")
    [[ -z "${TD_BOOT_MODE}" ]] && missing_opts+=("-m TD_BOOT_MODE")
    [[ -z "${INITRD_PATH}" ]] && missing_opts+=("-i INITRD_PATH")
    [[ -z "${KERNEL_PATH}" ]] && missing_opts+=("-k KERNEL_PATH")

    if [[ ${#missing_opts[@]} -gt 0 ]]; then
        echo "Error: Missing required option(s): ${missing_opts[*]}"
        usage
        exit 1
    fi

    if [[ "${TD_BOOT_MODE}" != "GET_QUOTE" && "${TD_BOOT_MODE}" != "TD_FDE_BOOT" ]]; then
        echo "Error: Invalid TD_BOOT_MODE. Must be either GET_QUOTE or TD_FDE_BOOT."
        usage
        exit 1
    fi
}

# Validate files exist
check_files_exist() {
    local missing_files=()

    # Check each file option
    [[ -n "${OVMF_PATH}" && ! -f "${OVMF_PATH}" ]] && missing_files+=("OVMF_PATH (-o)")
    [[ -n "${TD_IMG_PATH}" && ! -f "${TD_IMG_PATH}" ]] && missing_files+=("TD_IMG_PATH (-t)")
    [[ -n "${INITRD_PATH}" && ! -f "${INITRD_PATH}" ]] && missing_files+=("INITRD_PATH (-i)")
    [[ -n "${KERNEL_PATH}" && ! -f "${KERNEL_PATH}" ]] && missing_files+=("KERNEL_PATH (-k)")

    if [[ ${#missing_files[@]} -gt 0 ]]; then
        echo "Error: File(s) not found: ${missing_files[*]}"
        usage
        exit 1
    fi
}

process_args "$@"
validate_options "$@"
check_files_exist

set -e

PROCESS_NAME="td"

qemu-system-x86_64 \
    -accel kvm \
    -cpu host \
    -m 2G -smp 16 \
    -name ${PROCESS_NAME},process=${PROCESS_NAME},debug-threads=on \
    -object '{"qom-type":"tdx-guest","id":"tdx","quote-generation-socket":{"type": "vsock", "cid":"2","port":"4050"}}' \
    -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,hpet=off \
    -bios ${OVMF_PATH} \
    -kernel ${KERNEL_PATH} \
    -initrd ${INITRD_PATH} \
    -append "root=/dev/mapper/${LABEL_DEV_ROOTFS_DEC} console=ttyS0 cryptdevice=UUID=${UUID_PART_ROOTFS}:${LABEL_DEV_ROOTFS_DEC} td-boot-mode=${TD_BOOT_MODE}" \
    -drive file=${TD_IMG_PATH} \
    -device virtio-net-pci,netdev=nic0_td \
    -netdev user,id=nic0_td \
    -device vhost-vsock-pci,guest-cid=3 \
    -nographic \
    -nodefaults \
    -serial stdio \
    -pidfile /tmp/tdx-demo-td-pid.pid
