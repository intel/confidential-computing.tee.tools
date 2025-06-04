#!/bin/bash

# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Summary of the Script
# This script is designed to handle full-disk encryption for a TDX guest image.
# It supports two main boot modes: GET_QUOTE and TD_FDE_BOOT.
# Below is a summary of the script's functionality, detailing the steps taken for each boot mode.
#
# GET_QUOTE Boot Mode
# - cleanup_get_quote: Cleans up any remnants from a previous run, including unmounting partitions, disconnecting devices, and removing temporary files.
# - create_image: Creates an empty image file of the calculated size based on the specified partition sizes.
# - create_partitions: Sets up the partition layout for BIOS, UEFI, boot, and root filesystem in the created image and maps it to a loop device.
# - create_luks_partition: Encrypts the root partition with LUKS using a dummy key and opens it to a virtual device.
# - format_partitions: Formats the EFI, boot, and decrypted root partitions.
# - fill_rootfs: Copies data from the base image to the root partition, mounts necessary partitions, and sets up the root filesystem.
# - close_partitions: Closes the virtual device providing decrypted access to the root partition and detaches the loop device.
# - modify_ovmf: Enrolls TD boot mode and public key from key pair used for key retrieval into the OVMF firmware.
#
# TD_FDE_BOOT Boot Mode
# - cleanup_td_fde_boot: Cleans up any remnants from a previous run, including unmounting partitions and disconnecting devices.
# - reencrypt_luks_partition: Re-encrypts the existing LUKS partition with the provided key.
# - modify_ovmf: Enrolls the TD boot mode, KBS URL, and root filesystem key ID into the OVMF firmware.

MY_PATH="$(dirname "$(readlink -f "$0")")"
pushd ${MY_PATH}

# Determine the username of the user who initiated the script, even if it is being run with elevated privileges.
if [[ -z "$SUDO_USER" ]]; then
    LOGIN_USER=$(whoami)
else
    LOGIN_USER=$SUDO_USER
fi

# Define temporary directories used for following steps
PATH_TMP_DIR="$MY_PATH/tmp_fde"
PATH_MNT_ROOTFS=${PATH_TMP_DIR}/mnt_root
PATH_MNT_BOOT=${PATH_MNT_ROOTFS}/boot
PATH_MNT_EFI=${PATH_MNT_BOOT}/efi
PATH_MNT_NBT=${PATH_TMP_DIR}/mnt_nbd

# Define labels for encrypted root partition and for virtual device providing decrypted access to this partition.
# Label uses a hash of the script directory to make it unique for the invocation of this script instance.
MY_PATH_HASH=$(echo -n "$MY_PATH" | md5sum | cut -c1-8)
LABEL_PART_ROOTFS_ENC="rootfs-enc_${MY_PATH_HASH}"
LABEL_DEV_ROOTFS_DEC="rootfs-enc-dev_${MY_PATH_HASH}"

# Size of key used to encrypt root filesystem.
EXPECTED_K_RFS_SIZE=256

# Function cleans after last GET_QUOTE run, which might have failed at any point.
function cleanup_get_quote() {
    local PATH_IMG_IN=$1

    # Unmount anything mounted to directory used to mount partition from base image.
    if mount | grep $PATH_MNT_NBT >/dev/null; then
        umount $PATH_MNT_NBT
    fi

    # If any nbd is connected to base image, disconnect it.
    local nbd_line=$(ps m -C qemu-nbd --no-headers | grep "$PATH_IMG_IN")
    if [ -n "$nbd_line" ]; then
        # Extract the nbd device (e.g., /dev/nbd0)
        local nbd_device=$(echo "$nbd_line" | grep -oE '\-\-connect=/dev/nbd[0-9]+' | cut -d= -f2)

        if [ -n "$nbd_device" ]; then
            echo "Found $PATH_IMG_IN connected to $nbd_device. Disconnecting..."

            qemu-nbd --disconnect "$nbd_device"
        fi
    fi

    # Check if output image is associated with any loop device.
    # If it is, find corresponding loop device and unmount partitions individually.
    if losetup -a | grep $PATH_IMG_OUT >/dev/null; then
        # To not accidentally unmount system folders, make sure that PATH_MNT_ROOTFS is defined and set to a path inside the project directory.
        [ -n "$PATH_MNT_ROOTFS" ] && [[ "$PATH_MNT_ROOTFS" == $MY_PATH* ]] || exit 1

        if mount | grep -q ${PATH_MNT_ROOTFS}/dev/pts; then
            umount ${PATH_MNT_ROOTFS}/dev/pts
        fi
        if mount | grep -q ${PATH_MNT_ROOTFS}/dev; then
            umount ${PATH_MNT_ROOTFS}/dev
        fi
        if mount | grep -q ${PATH_MNT_ROOTFS}/run; then
            umount -f ${PATH_MNT_ROOTFS}/run
        fi
        if mount | grep -q ${PATH_MNT_ROOTFS}/tmp; then
            umount ${PATH_MNT_ROOTFS}/tmp
        fi
        if mount | grep -q ${PATH_MNT_ROOTFS}/sys; then
            umount -l ${PATH_MNT_ROOTFS}/sys
        fi
        if mount | grep -q ${PATH_MNT_ROOTFS}/proc; then
            umount ${PATH_MNT_ROOTFS}/proc
        fi

        if mount | grep ${PATH_MNT_ROOTFS} | grep -q ${PATH_MNT_EFI}; then
            umount ${PATH_MNT_EFI}
        fi
        if mount | grep ${PATH_MNT_ROOTFS} | grep -q ${PATH_MNT_BOOT}; then
            umount ${PATH_MNT_BOOT}
        fi
        if mount | grep -q ${PATH_MNT_ROOTFS}; then
            umount ${PATH_MNT_ROOTFS}
        fi

        # Close virtual device providing a decrypted view to encrypted root partition.
        if cryptsetup status "$LABEL_DEV_ROOTFS_DEC" 2>/dev/null | grep -q "is active"; then
            cryptsetup close $LABEL_DEV_ROOTFS_DEC
        fi

        # Find all loop devices attached to the encrypted image and detach them.
        local loop_devs=$(losetup -a | grep "$PATH_IMG_OUT" | cut -d: -f1)
        for loop_dev in $loop_devs; do
            losetup -d "$loop_dev"
        done
    fi

    # If present, remove old output image.
    rm -f $PATH_IMG_OUT

    # If present, remove temporary folder is to prepare output image in last run
    rm -rf $PATH_TMP_DIR
}

# Function cleans after last TD_FDE_BOOT run, which might have failed at any point.
function cleanup_td_fde_boot() {
    if losetup -a | grep $PATH_IMG_OUT >/dev/null; then
        # Close virtual device providing a decrypted view to encrypted root partition.
        if cryptsetup status "$LABEL_DEV_ROOTFS_DEC" 2>/dev/null | grep -q "is active"; then
            cryptsetup close $LABEL_DEV_ROOTFS_DEC
        fi

        # Find all loop devices attached to the encrypted image and detach them.
        local loop_devs=$(losetup -a | grep "$PATH_IMG_OUT" | cut -d: -f1)
        for loop_dev in $loop_devs; do
            losetup -d "$loop_dev"
        done
    fi

    # Remove named pipes
    rm -f /tmp/key_old_fifo /tmp/key_new_fifo
}

function usage() {
    cat <<EOF
Usage: $(basename "$0") <TD boot mode> [OPTION]...

Boot modes:
    GET_QUOTE       Perform dummy encryption, which is used to retrieve TD quote from TD.
    TD_FDE_BOOT     Perform encryption with provided key.

Options:
    -c <KBS_CERT_PATH>      Path to TLS certificate of ITA KBS; mandatory for TD boot mode \"GET_QUOTE\", forbidden for TD boot mode \"TD_FDE_BOOT\"
    -p <PATH_IMG_IN>        Path to the input image; mandatory for TD boot mode \"GET_QUOTE\" and \"TD_FDE_BOOT\"
    -e <PATH_IMG_OUT>       Path to the output image; optional for TD boot mode \"GET_QUOTE\" and \"TD_FDE_BOOT\"; default is \"GET_QUOTE\" added as a postfix for \"GET_QUOTE\" and \"TD_FDE_BOOT\" added as a postfix for \"TD_FDE_BOOT\".
    -f <PK_KR_PATH>         Path to the public key from key pair used for key retrieval
    -u <KBS_URL>            URL of ITA KBS; mandatory for TD boot mode \"TD_FDE_BOOT\", forbidden for TD boot mode \"GET_QUOTE\"
    -k <K_RFS_HEX>          Key for encryption of root filesystem in hex encoding; mandatory for TD boot mode \"TD_FDE_BOOT\", forbidden for TD boot mode \"GET_QUOTE\"
    -i <K_RFS_ID>           Key ID used by ITA KBS for root filesystem encryption key; mandatory for TD boot mode \"TD_FDE_BOOT\", forbidden for TD boot mode \"GET_QUOTE\"
    -d <TMP_K_RFS>          Path to store/read the dummy key used for encryption of root filesystem; mandatory for TD boot mode \"GET_QUOTE\" and \"TD_FDE_BOOT\"

    -r <SIZE_PART_ROOTFS>   Size of root filesystem partition; optional for TD boot mode \"GET_QUOTE\", forbidden for TD boot mode \"TD_FDE_BOOT\"; default is 10GB
    -b <SIZE_PART_BOOT>     Size of boot partition; optional for TD boot mode \"GET_QUOTE\", forbidden for TD boot mode \"TD_FDE_BOOT\"; default is 2GB

    -h                      Show this help
EOF
}

function process_args() {
    # Check if no arguments were provided
    if [[ $# -eq 0 ]]; then
        echo "No argument was provided"
        usage
        exit 1
    fi

    # Check if help option is provided anywhere in arguments
    for arg in "$@"; do
        if [[ "$arg" == "-h" ]]; then
            usage
            exit 0
        fi
    done


    if [[ "$1" != "TD_FDE_BOOT" && "$1" != "GET_QUOTE" ]]; then
        echo "Invalid TD boot mode '$1'"
        usage
        exit 1
    fi

    TD_BOOT_MODE=$1
    shift

    while getopts "h:r:b:p:k:i:u:c:e:f:d:" option; do
        case "$option" in
        r) SIZE_PART_ROOTFS=$OPTARG ;;
        b) SIZE_PART_BOOT=$OPTARG ;;
        p) PATH_IMG_IN=$OPTARG ;;
        k) K_RFS_HEX=$OPTARG ;;
        i) K_RFS_ID=$OPTARG ;;
        u) KBS_URL=$OPTARG ;;
        c) KBS_CERT_PATH=$OPTARG ;;
        e) PATH_IMG_OUT=$OPTARG ;;
        f) PK_KR_PATH=$OPTARG ;;
        d) TMP_K_RFS=$OPTARG ;;
        h)
            usage
            exit 0
            ;;
        *)
            echo "Invalid option '-$OPTARG'"
            usage
            exit 1
            ;;
        esac
    done
}

check_params_filled() {
    local empty_vars=()

    # Loop through all arguments passed to the function.
    for var_name in "$@"; do
         # Indirect expansion to get the value of the variable
        local value="${!var_name}"
        if [ -z "$value" ]; then
            empty_vars+=("$var_name")
        fi
    done

    # Check if any variables are empty
    if [ ${#empty_vars[@]} -ne 0 ]; then
        echo "Error: The following mandatory parameters were not provided: ${empty_vars[*]}"
        usage
        exit 1
    fi

    return 0
}

# Function to check if specified parameters are empty and return an error if this is not the case.
check_params_empty() {
    local non_empty_vars=()

    # Loop through all arguments passed to the function.
    for var_name in "$@"; do
         # Indirect expansion to get the value of the variable
        local value="${!var_name}"
        if [ -n "$value" ]; then
            non_empty_vars+=("$var_name")
        fi
    done

    # Check if any variables are not empty
    if [ ${#non_empty_vars[@]} -ne 0 ]; then
        echo "Error: The following parameters should not be provided: ${non_empty_vars[*]}"
        usage
        exit 1
    fi

    return 0
}

# Check validity of provided arguments
function check_args_env() {
    check_params_filled PATH_IMG_IN TMP_K_RFS

    if [ ! -f $TMP_K_RFS ]; then
        echo "Cannot find file with dummy key used for the initial encryption of root file system at \"$TMP_K_RFS\"."
        exit 1
    fi

    if [ ! -f $PATH_IMG_IN ]; then
        echo "Input image not present at \"$PATH_IMG_IN\"."
        exit 1
    fi

    if [[ $TD_BOOT_MODE == "GET_QUOTE" ]]; then
        check_params_filled KBS_CERT_PATH PK_KR_PATH
        check_params_empty KBS_URL K_RFS_HEX K_RFS_ID

        if [ ! -f $PK_KR_PATH ]; then
            echo "Public key from key pair used for key retrieval is not found at provided path \"$PK_KR_PATH\"."
            usage
            exit 1
        fi

        if [ ! -f $KBS_CERT_PATH ]; then
            echo "TLS certificate of ITA KBS not found at provided path \"$KBS_CERT_PATH\"."
            usage
            exit 1
        fi

        # Input image must be an qcow2 image.
        if [[ "$PATH_IMG_IN" != *".qcow2" ]]; then
            echo "Error: For GET_QUOTE mode, the input file must have .qcow2 extension."
            exit 1
        fi

        if [ -z "$PATH_IMG_OUT" ]; then
            PATH_IMG_OUT="${PATH_IMG_IN%.*}_GET_QUOTE.img"
        else
            if [[ "$PATH_IMG_OUT" != *".img" ]]; then
                echo "Error: For GET_QUOTE mode, the output file must have .img extension."
                exit 1
            fi

            if [[ "$(realpath "$PATH_IMG_IN")" == "$(realpath "$PATH_IMG_OUT")" ]]; then
                echo "Error: The output image path cannot be the same as the input image path."
                exit 1
            fi
        fi

    elif [[ $TD_BOOT_MODE == "TD_FDE_BOOT" ]]; then
        check_params_filled KBS_URL K_RFS_HEX K_RFS_ID
        check_params_empty KBS_CERT_PATH SIZE_PART_ROOTFS SIZE_PART_BOOT PK_KR_PATH

        # Input image must be an raw image.
        if [[ "$PATH_IMG_IN" != *".img" ]]; then
            echo "Error: For TD_FDE_BOOT mode, the input file must have .img extension."
            exit 1
        fi

        if [[ ${#K_RFS_HEX} -ne $((EXPECTED_K_RFS_SIZE / 4)) ]]; then
            echo "Key for encryption of root filesystem must be ${EXPECTED_K_RFS_SIZE} bits long."
            usage
            exit 1
        fi


        if [ -z "$PATH_IMG_OUT" ]; then
            # If no output file path was provided, create a default output file path
            # If the input file path ends with "_GET_QUOTE.img", replace that suffix with "_TD_FDE_BOOT.img"
            # Otherwise, append "_TD_FDE_BOOT" before the extension
            if [[ "$PATH_IMG_IN" == *"_GET_QUOTE.img" ]]; then
                PATH_IMG_OUT="${PATH_IMG_IN%_GET_QUOTE.img}_TD_FDE_BOOT.img"
            else
                PATH_IMG_OUT="${PATH_IMG_IN%.*}_TD_FDE_BOOT.img"
            fi
        fi

        if [[ "$PATH_IMG_OUT" != *".img" ]]; then
            echo "Error: For TD_FDE_BOOT mode, the output file must have .img extension."
            exit 1
        fi

        # If input and output paths are different, copy image before re-encryption.
        # Otherwise, we do a re-encryption in-place.
        if [[ "$(realpath "$PATH_IMG_IN")" == "$(realpath "$PATH_IMG_OUT")" ]]; then
            echo "Input and output paths are the same. No copy needed for re-encryption."
        else
            cp -f "$PATH_IMG_IN" "$PATH_IMG_OUT"
        fi
    fi
}

function modify_ovmf() {
    # Create virtual environment for Python if it does not already exist
    if [ -e my_venv/bin/activate ]; then
        echo "Found python virtual environment folder; using it"
        source my_venv/bin/activate
        if [[ -z "$(command -v ovmfkeyenroll)" ]]; then
            python3 -m pip install ovmfkeyenroll
        fi
    else
        python3 -m venv my_venv
        source my_venv/bin/activate
        python3 -m pip install ovmfkeyenroll
    fi

    rm -rf $OVMF_OUTPUT

    # Enroll TD boot mode to OVMF.
    printf $TD_BOOT_MODE>td_boot_mode
    VARIABLE_NAME="TDBOOTMODE"
    VARIABLE_GUID="8093baf3-b42c-4a46-9c60-02888f011f03"
    VARIABLE_VALUE_FILE_PATH="td_boot_mode"
    python3 enroll_vars.py -i ${OVMF_INPUT} -o ${OVMF_OUTPUT} -n $VARIABLE_NAME -g $VARIABLE_GUID -d $VARIABLE_VALUE_FILE_PATH

    if [[ $TD_BOOT_MODE == "GET_QUOTE" ]]; then
        # Enroll public key for key enrollment (PK_KR) to OVMF.
        VARIABLE_NAME="PK_KR"
        VARIABLE_GUID="4517e507-9b4b-479d-b422-2562900361e3"
        VARIABLE_VALUE_FILE_PATH=$PK_KR_PATH
        python3 enroll_vars.py -i ${OVMF_OUTPUT} -o ${OVMF_OUTPUT} -n $VARIABLE_NAME -g $VARIABLE_GUID -d $VARIABLE_VALUE_FILE_PATH
    elif [[ $TD_BOOT_MODE == "TD_FDE_BOOT" ]]; then
        # Enroll URL of KBS to OVMF.
        printf $KBS_URL>kbs_url
        VARIABLE_NAME="KBSURL"
        VARIABLE_GUID="0d9b4a60-e0bf-4a66-b9b1-db1b98f87770"
        VARIABLE_VALUE_FILE_PATH="kbs_url"
        python3 enroll_vars.py -i ${OVMF_OUTPUT} -o ${OVMF_OUTPUT} -n $VARIABLE_NAME -g $VARIABLE_GUID -d $VARIABLE_VALUE_FILE_PATH

        # Enroll id of root filesystem key that was assigned by KBS, to OVMF.
        printf $K_RFS_ID>kbs_k_rfs_id
        VARIABLE_NAME="KBSKRFSID"
        VARIABLE_GUID="dc001d1f-60a1-4e1e-853e-42e9ab0e8b88"
        VARIABLE_VALUE_FILE_PATH="kbs_k_rfs_id"
        python3 enroll_vars.py -i ${OVMF_OUTPUT} -o ${OVMF_OUTPUT} -n $VARIABLE_NAME -g $VARIABLE_GUID -d $VARIABLE_VALUE_FILE_PATH

        rm -rf kbs_url kbs_k_rfs_id
    fi

    # Cleanup
    rm -rf td_boot_mode
    deactivate
}

# Function sets partition layout for BIOS, UEFI, boot, and root filesystem in the passed image.
# It then maps the passed image to a loop device.
# Parameters:
#   - SIZE_PART_BOOT: The size of the boot partition.
#   - PATH_IMAGE: The path to the image file for which the partitions are set.
function create_partitions() {
    local SIZE_PART_BOOT=$1
    local PATH_IMAGE=$2

    local NUM_ROOTFS_PART=1
    local NUM_BIOS_PART=14
    local NUM_UEFI_PART=15
    local NUM_BOOT_PART=16

    # Set partition layout for BIOS, UEFI, boot, and root filesystem in the passed image.
    # Note that Root FS has to be defined last, because it used the remaining size.
    # Note that the install script later installs GRUB in the BIOS partition
    sgdisk --clear \
        --new ${NUM_BIOS_PART}::+1M --typecode=${NUM_BIOS_PART}:ef02 --change-name=${NUM_BIOS_PART}:'bios' \
        --new ${NUM_UEFI_PART}::+100M --typecode=${NUM_UEFI_PART}:ef00 --change-name=${NUM_UEFI_PART}:'uefi' \
        --new ${NUM_BOOT_PART}::+$SIZE_PART_BOOT --typecode=${NUM_BOOT_PART}:8300 --change-name=${NUM_BOOT_PART}:'boot' \
        --new ${NUM_ROOTFS_PART}::-0 --typecode=${NUM_ROOTFS_PART}:8300 --change-name=${NUM_ROOTFS_PART}:'rootfs' \
        $PATH_IMAGE

    # Find an unused loop device and attach the image to it.
    local LOOPDEV=$(losetup --find --show $PATH_IMAGE)

    # Inform the operating system kernel of partition table changes of the image file.
    partprobe ${LOOPDEV}

    # Return info about used loop device and name of created partitions.
    echo "${LOOPDEV}|${LOOPDEV}p${NUM_UEFI_PART}|${LOOPDEV}p${NUM_BOOT_PART}|${LOOPDEV}p${NUM_ROOTFS_PART}"
}

# Create a LUKS (Linux Unified Key Setup) encrypted partition.
# Parameters:
#   - PART: Partition to encrypt.
#   - LABEL_PART_ENC: Label of the encrypted partition.
#   - LABEL_DEV_DEC: Label of virtual device that provides a decrypted view of the data in the encrypted partition.
function create_luks_partition() {
    local PART=$1
    local LABEL_PART_ENC=$2
    local LABEL_DEV_DEC=$3

    # Use dummy key for the initial encryption of root file system.
    local KEY_HEX=$(< ${TMP_K_RFS})

    # Decode hex-encoded key, and set up an encrypted partition using LUKS2 with AES-GCM encryption using a 256bit key and AEAD for integrity protection.
    echo -n "$KEY_HEX" | xxd -r -p |
        cryptsetup -v -q luksFormat --encrypt --type luks2 \
            --cipher aes-gcm-random --integrity aead --key-size 256 $PART

    # Set a label for the encrypted partition
    cryptsetup -v config --label $LABEL_PART_ENC $PART

    # Decode hex-encoded key, and open the encrypted partition creating a virtual device providing decrypted access to encrypted partition.
    echo -n "$KEY_HEX" | xxd -r -p |
        cryptsetup luksOpen --key-size 256 $PART "${LABEL_DEV_DEC}"

    # Print/return path of virtual device providing decrypted access to encrypted partition.
    echo "/dev/mapper/${LABEL_DEV_DEC}"
}

# Function to re-encrypt the existing LUKS partition with the provided key.
function reencrypt_luks_partition() {
    local key_new_hex=$1
    local PATH_IMG_OUT=$2
    local label_dev_rootfs_dec=$3

    # Find an unused loop device and attach the image to it.
    local loop_dev=$(losetup --find --show $PATH_IMG_OUT)

    # Inform the operating system kernel of partition table changes of the image file.
    partprobe ${loop_dev}

    # Determine the rootfs partition.
    local part_rootfs=$(lsblk -lno NAME,PARTLABEL | grep 'rootfs' | awk '{print $1}' | tail -n 1)
    part_rootfs="/dev/${part_rootfs}"

    # Read dummy key used for initial root file system encryption.
    local key_old_hex=$(< ${TMP_K_RFS})

    # Add the new key to the LUKS partition using named pipes
    mkfifo /tmp/key_old_fifo /tmp/key_new_fifo
    echo -n "$key_old_hex" | xxd -r -p > /tmp/key_old_fifo &
    echo -n "$key_new_hex" | xxd -r -p > /tmp/key_new_fifo &

    # Add the new key to the LUKS partition.
    cryptsetup luksAddKey $part_rootfs --key-file=/tmp/key_old_fifo --new-keyfile=/tmp/key_new_fifo || {
        echo "Error: Failed to add new key to LUKS partition, returned with status: $?."
        cleanup_td_fde_boot
        exit 1
    }
    rm -f /tmp/key_old_fifo /tmp/key_new_fifo

    # Remove the old key from the LUKS partition.
    echo -n "$key_old_hex" | xxd -r -p |
        cryptsetup luksRemoveKey $part_rootfs --key-file - || {
        echo "Error: Failed to remove old key from LUKS partition, returned with status: $?."
        cleanup_td_fde_boot
        exit 1
    }

    # Check that LUKS partition can be opened with the new key.
    echo -n "$key_new_hex" | xxd -r -p |
        cryptsetup luksOpen --key-size 256 $part_rootfs "${label_dev_rootfs_dec}" --key-file - || {
        echo "Error: Failed to open LUKS partition with the new key, returned with status: $?."
        cleanup_td_fde_boot
        exit 1
    }

    # Close virtual device providing decrypted access to root partition.
    cryptsetup close $label_dev_rootfs_dec || {
        echo "Error: Failed to close virtual device providing decrypted access to root partition, returned with status: $?."
        cleanup_td_fde_boot
        exit 1
    }

    # Detach loop device.
    losetup -d $loop_dev
}

# Format EFI partition, boot partition, and device providing decrypted access to encrypted root partition.
# Parameters:
#   - PART_EFI: EFI partition that should be formatted.
#   - PART_BOOT: Boot partition that should be formatted.
#   - DEV_ROOTFS_DEC: Virtual device providing a decrypted view to encrypted root partition that should be formatted.
function format_partitions() {
    local PART_EFI=$1
    local PART_BOOT=$2
    local DEV_ROOTFS_DEC=$3

    # Create filesystems for EFI partition.
    mkfs.fat -F32 $PART_EFI

    # Relabel because fat formatting cleared ext label.
    fatlabel $PART_EFI uefi

    # Format boot partition and device with access to encrypted root partition.
    mkfs.ext4 -F -L "boot" $PART_BOOT
    mkfs.ext4 -F $DEV_ROOTFS_DEC
}

# This function creates the root filesystem in virtual device providing decrypted access to encrypted root partition.
# It
# - Copies data from the base image to the root partition.
# - Copies the FDE solution binaries and data into the root partition.
# - Formats and prepares the root partition.
# - Mounts the boot and efi partitions inside the root partition.
# - Provides the necessary system interfaces and directories within the chroot environment.
# - Copies the installation script into the root partition and executes it.
function fill_rootfs() {
    local PART_EFI=$1
    local PART_BOOT=$2
    local DEV_ROOTFS_DEC=$3
    local PART_ROOTFS=$4
    local PATH_IMG_IN=$5
    local KBS_CERT_PATH=$6
    local LABEL_PART_ROOTFS_ENC=$7
    local LABEL_DEV_ROOTFS_DEC=$8

    # Ensures that the nbd module is available
    if ! lsmod | grep -wq nbd; then
        modprobe nbd max_part=8
    fi

    # Create temporary directory and mount virtual device providing decrypted access to encrypted root partition to this directory.
    mkdir -p ${PATH_MNT_ROOTFS}
    mount $DEV_ROOTFS_DEC ${PATH_MNT_ROOTFS}

    # Mount the boot partition inside the "boot" folder of the root partition.
    mkdir -p ${PATH_MNT_BOOT}
    mount $PART_BOOT ${PATH_MNT_BOOT}/

    # Mount the efi partition inside the "boot/efi" folder of the root partition.
    mkdir -p ${PATH_MNT_EFI}
    mount $PART_EFI ${PATH_MNT_EFI}

    # Cleanup files that are not needed
    rm -rf ${PATH_MNT_ROOTFS}/lost+found
    rm -rf ${PATH_MNT_ROOTFS}/boot/lost+found

    # Find the first unused network block device (nbd) and bind the base image to it.
    local UNUSED_DEV_NBD=""
    for TMP_DEV_NBD in /dev/nbd*; do
        if ! grep -q "$TMP_DEV_NBD" /proc/mounts && [ ! -e "${TMP_DEV_NBD}p1" ]; then
            UNUSED_DEV_NBD="$TMP_DEV_NBD"
            break
        fi
    done
    if [ -z "$UNUSED_DEV_NBD" ]; then
        echo "Error: No unused NBD device found."
        exit 1
    else
        echo "Using NBD device $UNUSED_DEV_NBD."
    fi
    qemu-nbd --connect="$UNUSED_DEV_NBD" "$PATH_IMG_IN"
    sleep 3

    # Create a temporary directory that is used to mount partitions from the base image to.
    mkdir -p ${PATH_MNT_NBT}

    # Copy the content of rootfs partition from base image to the rootfs partition.
    mount ${UNUSED_DEV_NBD}p1 ${PATH_MNT_NBT}
    cp -rfp ${PATH_MNT_NBT}/* ${PATH_MNT_ROOTFS}
    umount ${PATH_MNT_NBT}

    # Copy the content of the 16th partition of the base image to the boot directory in the root partition.
    mount ${UNUSED_DEV_NBD}p16 ${PATH_MNT_NBT}
    cp -rf ${PATH_MNT_NBT}/* ${PATH_MNT_BOOT}
    umount ${PATH_MNT_NBT}

    # Disconnect base image from nbd
    qemu-nbd --disconnect ${UNUSED_DEV_NBD}

    # Copy FDE solution binaries into the root partition.
    pushd ${MY_PATH}/../../fde-binaries/
    cp target/release/fde-decrypt-image ${PATH_MNT_ROOTFS}/sbin/
    popd

    # Copy initramfs scripts, initramfs modules, and initramfs hooks into the root partition.
    pushd initramfs
    cp scripts/init-premount/fde-agent \
        ${PATH_MNT_ROOTFS}/usr/share/initramfs-tools/scripts/init-premount/
    cp modules ${PATH_MNT_ROOTFS}/etc/initramfs-tools/
    cp -r hooks/* ${PATH_MNT_ROOTFS}/usr/share/initramfs-tools/hooks/
    popd

    # Copy a netplan into the root partition.
    cp netplan.yaml ${PATH_MNT_ROOTFS}/etc/netplan

    # Copy KBS certificate into the root partition.
    cp $KBS_CERT_PATH ${PATH_MNT_ROOTFS}/etc/kbs.crt

    # Provide the necessary system interfaces and directories within the chroot environment.
    mount -t proc none ${PATH_MNT_ROOTFS}/proc
    mount -t sysfs none ${PATH_MNT_ROOTFS}/sys
    mount -t tmpfs none ${PATH_MNT_ROOTFS}/tmp
    mount --bind /run ${PATH_MNT_ROOTFS}/run
    mount --bind /dev ${PATH_MNT_ROOTFS}/dev
    mount --bind /dev/pts ${PATH_MNT_ROOTFS}/dev/pts

    # Copy installation script into root partition, execute it, and remove it.
    cp scripts/install ${PATH_MNT_ROOTFS}/tmp/
    chroot ${PATH_MNT_ROOTFS}/ /bin/bash tmp/install $PART_ROOTFS $LABEL_PART_ROOTFS_ENC $LABEL_DEV_ROOTFS_DEC
    rm ${PATH_MNT_ROOTFS}/tmp/install

    # Clean up mount points
    umount ${PATH_MNT_ROOTFS}/dev/pts
    umount ${PATH_MNT_ROOTFS}/dev
    umount ${PATH_MNT_ROOTFS}/run
    umount ${PATH_MNT_ROOTFS}/tmp
    umount -l ${PATH_MNT_ROOTFS}/sys
    umount ${PATH_MNT_ROOTFS}/proc
    umount ${PATH_MNT_EFI}
    umount ${PATH_MNT_BOOT}
    umount ${PATH_MNT_ROOTFS}/
}

function close_partitions() {
    local DEV_ROOTFS_DEC=$1
    local LOOPDEV=$2

    # Close virtual device providing decrypted access to root partition.
    cryptsetup close $DEV_ROOTFS_DEC

    # Detach loop device .
    losetup -d $LOOPDEV
}

# Calculate the size of the output image based on specified partition size and create an empty image file of that size.
function create_image() {
    local SIZE_PART_ROOTFS=$1
    local SIZE_PART_BOOT=$2
    local PATH_IMG_OUT=$3

    # Calculate total image size in bytes based on defined size values.
    # Reserve 1MB for BIOS and 100MB for EFI.
    local SIZE_IMAGE=$(echo "($SIZE_PART_ROOTFS+$SIZE_PART_BOOT+101MB)" |
        sed -e 's/KB/\*1024/g' -e 's/MB/\*1048576/g' -e 's/GB/\*1073741824/g' | bc)

    # Create empty image file of calculated size to represent output disk
    truncate --size "$SIZE_IMAGE" "$PATH_IMG_OUT"
}

# Function to handle the GET_QUOTE boot mode
function handle_get_quote() {
    echo "=============== Cleanup Last Run ==============="

    cleanup_get_quote "$PATH_IMG_IN"

    echo "=============== Create Empty Image ==============="

    # If not set per parameter, set size of rootfs partition and boot partition to default values.
    SIZE_PART_ROOTFS=${SIZE_PART_ROOTFS:-10GB}
    SIZE_PART_BOOT=${SIZE_PART_BOOT:-2GB}

    # Create an empty image
    create_image "$SIZE_PART_ROOTFS" "$SIZE_PART_BOOT" "$PATH_IMG_OUT"

    echo "=============== Create Image Partitions ==============="

    # Create partitions
    IFS='|' read -r LOOPDEV PART_EFI PART_BOOT PART_ROOTFS <<< "$(create_partitions "$SIZE_PART_BOOT" "$PATH_IMG_OUT" | tail -n 1)"
    echo -e "LOOPDEV:${LOOPDEV} \nROOT:${PART_ROOTFS} \nEFI:${PART_EFI} \nBOOT:${PART_BOOT}"

    echo "=============== Encrypt RootFS and Open =========="

    # Encrypt root partition with LUKS and open the partition to a virtual device.
    # A hardcoded dummy key is used for the encryption.
    DEV_ROOTFS_DEC=$(create_luks_partition  "$PART_ROOTFS" "$LABEL_PART_ROOTFS_ENC" "$LABEL_DEV_ROOTFS_DEC" | tail -n 1)
    echo "Virtual device providing decrypted access to encrypted root partition: $DEV_ROOTFS_DEC"

    echo "=============== Format Partitions =========="

    format_partitions "$PART_EFI" "$PART_BOOT" "$DEV_ROOTFS_DEC"
    echo "Formatting done"

    echo "=============== Fill Opened RootFS ========"

    # Fill RootFS with needed files
    fill_rootfs "$PART_EFI" "$PART_BOOT" "$DEV_ROOTFS_DEC" "$PART_ROOTFS" "$PATH_IMG_IN" "$KBS_CERT_PATH" "$LABEL_PART_ROOTFS_ENC" "$LABEL_DEV_ROOTFS_DEC"

    echo "=============== Close Partitions ============="

    # Deactivate partitions
    close_partitions "$DEV_ROOTFS_DEC" "$LOOPDEV"

    echo "=============== Enroll Variables into OVMF ============="

    # Enroll variables in OVMF
    modify_ovmf
}

# Function to handle the TD_FDE_BOOT boot mode
function handle_td_fde_boot() {
    echo "=============== Cleanup Last Run ==============="

    cleanup_td_fde_boot

    echo "=============== Re-encrypt Existing LUKS Partition ==============="

    # Re-encrypt the existing LUKS partition with the provided key.
    reencrypt_luks_partition "$K_RFS_HEX" "$PATH_IMG_OUT" "$LABEL_DEV_ROOTFS_DEC"

    echo "=============== Enroll Variables into OVMF ============="

    # Enroll variables in OVMF
    modify_ovmf
}

# Function to perform cleanup when script is interrupted
function cleanup_on_interrupt() {
    echo "=============== Script interrupted in $TD_BOOT_MODE mode - Cleaning up resources ==============="

    # Use existing cleanup functions based on boot mode
    if [[ "$TD_BOOT_MODE" == "GET_QUOTE" ]]; then
        cleanup_get_quote "$PATH_IMG_IN"
    elif [[ "$TD_BOOT_MODE" == "TD_FDE_BOOT" ]]; then
        cleanup_td_fde_boot
    fi

    echo "=============== Cleanup completed ==============="
}

set -e

echo "=============== Build Start in mode $TD_BOOT_MODE ==============="
echo "=============== Check Validity of Parameters ==============="

process_args "$@"

check_args_env

# Setup trap to catch interruptions
trap cleanup_on_interrupt SIGINT

OVMF_INPUT=${MY_PATH}/../../data/ovmf-extracted/usr/share/ovmf/OVMF.tdx.fd
OVMF_OUTPUT=OVMF_${TD_BOOT_MODE}.fd

# Main script execution
if [[ $TD_BOOT_MODE == "GET_QUOTE" ]]; then
    handle_get_quote "$@"
elif [[ $TD_BOOT_MODE == "TD_FDE_BOOT" ]]; then
    handle_td_fde_boot "$@"
else
    echo "Invalid TD boot mode '$TD_BOOT_MODE'"
    usage
    exit 1
fi

echo "=============== Set Owner of Created OVMF and TD Image ============="
chown $LOGIN_USER:$LOGIN_USER $OVMF_OUTPUT
chown $LOGIN_USER:$LOGIN_USER $PATH_IMG_OUT

# Output full paths of the created files
echo "=============== Created Files ================"
echo "OVMF_PATH: $(realpath $OVMF_OUTPUT)"
echo "IMAGE_PATH: $(realpath $PATH_IMG_OUT)"

echo "=============== Build End ================"

popd
