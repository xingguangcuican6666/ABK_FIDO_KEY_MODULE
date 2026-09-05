#!/usr/bin/env bash

abk_fido_install_kernel_files() {
  local common_dir
  common_dir="$(abk_common_dir)"

  abk_require_dir "$common_dir/drivers"
  abk_require_dir "$common_dir/include/linux"
  abk_require_file "$common_dir/drivers/Kconfig"
  abk_require_file "$common_dir/drivers/Makefile"

  mkdir -p "$common_dir/drivers/abk_fido_key"
  cp -a "$MODULE_DIR/files/drivers/abk_fido_key/." "$common_dir/drivers/abk_fido_key/"
  cp -a "$MODULE_DIR/files/include/linux/abk_fido_key.h" "$common_dir/include/linux/abk_fido_key.h"

  abk_append_line_once "$common_dir/drivers/Kconfig" 'source "drivers/abk_fido_key/Kconfig"'
  abk_append_line_once "$common_dir/drivers/Makefile" 'obj-$(CONFIG_ABK_FIDO_KEY) += abk_fido_key/'
}

abk_fido_patch_usb_gadget() {
  local common_dir configfs
  common_dir="$(abk_common_dir)"
  configfs="$common_dir/drivers/usb/gadget/configfs.c"

  abk_require_file "$configfs"
  python3 "$MODULE_DIR/scripts/patch_configfs_for_abk_fido.py" "$configfs"
  # Fail the build if the FIDO interface injection is missing.
  grep -q "abk_fido_key_prepare_config" "$configfs" \
    || abk_die "ABK FIDO configfs patch missing the prepare_config injection"
  grep -q "abk_fido_key_release_config" "$configfs" \
    || abk_die "ABK FIDO configfs patch missing the release_config injection"
}

abk_fido_patch_kernelsu_sepolicy() {
  local common_dir rules
  common_dir="$(abk_common_dir)"
  rules="$common_dir/drivers/kernelsu/selinux/rules.c"

  abk_require_file "$rules"
  python3 "$MODULE_DIR/scripts/patch_kernelsu_sepolicy_for_abk_fido.py" "$rules"
  grep -q "ABK FIDO: allow kernel domain access to the persisted metadata store." "$rules" \
    || abk_die "ABK FIDO KernelSU sepolicy patch missing metadata_file allow rules"
}

abk_fido_enable_config() {
  abk_enable_config CONFIG_ABK_FIDO_KEY
  abk_enable_config CONFIG_ABK_FIDO_KEY_CTAP2
  abk_enable_config CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH
  abk_enable_config CONFIG_ABK_FIDO_KEY_PERSIST_METADATA
  abk_enable_config CONFIG_ABK_FIDO_KEY_PERSIST_ADB_DATA

  # Fail the build instead of shipping a phone that cannot enumerate the key.
  grep -q "^CONFIG_ABK_FIDO_KEY=y\$" "$DEFCONFIG" \
    || abk_die "CONFIG_ABK_FIDO_KEY missing from $DEFCONFIG"
  grep -q "^CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH=y\$" "$DEFCONFIG" \
    || abk_die "CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH missing from $DEFCONFIG"
}
