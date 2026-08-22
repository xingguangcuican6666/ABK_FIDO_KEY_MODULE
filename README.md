# ABK FIDO Key Module

`abk_fido_key_module` is an ABK custom external kernel module that turns an
Android phone build into a composite USB FIDO2 security key.

`abk_fido_key_module` 是一个 ABK 自定义外部内核模块，用来把 Android
手机侧内核扩展成一个复合 USB FIDO2 Security Key。

Current version / 当前版本: `0.2.0`

## Overview / 项目概览

This module installs an out-of-tree kernel driver, patches the Android USB
gadget configfs flow, and auto-attaches an extra FIDO HID interface to the
active USB configuration.

这个模块会安装一个外部内核驱动，patch Android USB gadget 的 configfs
流程，并在当前激活的 USB 配置上自动追加一个 FIDO HID 接口。

What it adds / 它会增加这些内容:

- `common/drivers/abk_fido_key`
- `common/include/linux/abk_fido_key.h`
- `CONFIG_ABK_FIDO_KEY`
- `CONFIG_ABK_FIDO_KEY_CTAP2`
- `CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH`
- `CONFIG_ABK_FIDO_KEY_PERSIST_METADATA`
- `CONFIG_ABK_FIDO_KEY_PERSIST_ADB_DATA` (compatibility toggle)
- `app/`: optional Android companion that mirrors the kernel store blob into a
  SQLite database persisted on `/metadata`

## Repository Layout / 仓库结构

- `setup.sh`: external module entrypoint used by the ABK build hook.
- `module.conf`: module metadata, version, and supported stages.
- `scripts/`: helper shell and Python patch scripts, including the KernelSU
  SELinux policy patcher used during external-module injection.
- `files/drivers/abk_fido_key/`: kernel driver source, Kconfig, and Makefile.
- `files/include/linux/abk_fido_key.h`: public kernel header used by the
  configfs injection point.
- `app/`, `build.gradle.kts`, `settings.gradle.kts`: minimal Android companion
  app project for the metadata-backed SQLite mirror.

## Integration / 接入方式

### Prerequisites / 前置条件

- An ABK or `new_test` style kernel build environment with `KERNEL_ROOT` and a
  `common/` kernel tree.
- `python3` available in the build environment.
- A `common/drivers/usb/gadget/configfs.c` layout compatible with the patch
  anchors used by `scripts/patch_configfs_for_abk_fido.py`.
- Root access on-device if you want the companion app to mirror the SQLite
  database into `/metadata`.

### Generic Example / 通用示例

Add the module to `new_test/.local-build/env.sh`:

```bash
export USE_CUSTOM_EXTERNAL_MODULES="true"
export CUSTOM_EXTERNAL_MODULES="/abs/path/to/abk_fido_key_module;after_patch|/abs/path/to/abk_fido_key_module;before_build"
```

### Repository URL Example / 仓库 URL 示例

If your ABK external-module loader supports Git URLs directly, you can also use
the public repository address:

如果你的 ABK 外部模块加载器支持直接拉取 Git URL，也可以直接使用公开仓库地址：

```bash
export USE_CUSTOM_EXTERNAL_MODULES="true"
export CUSTOM_EXTERNAL_MODULES="https://github.com/xingguangcuican6666/ABK_FIDO_KEY_MODULE.git;after_patch|https://github.com/xingguangcuican6666/ABK_FIDO_KEY_MODULE.git;before_build"
```

### Local Example / 当前本地示例

```bash
export USE_CUSTOM_EXTERNAL_MODULES="true"
export CUSTOM_EXTERNAL_MODULES="/run/media/xingguangcuican/Project/kernelexp/new_test/abk_fido_key_module;after_patch|/run/media/xingguangcuican/Project/kernelexp/new_test/abk_fido_key_module;before_build"
```

Then rebuild:

```bash
./rebuild.sh --reseed
```

## Stage Behavior / 阶段行为

- `after_patch`: install kernel files and patch
  `common/drivers/usb/gadget/configfs.c` plus
  `common/drivers/kernelsu/selinux/rules.c`.
- `before_build`: do everything from `after_patch`, then enable the required
  `CONFIG_ABK_FIDO_KEY*` symbols in `DEFCONFIG`, including the metadata
  persistence toggle.

The patch injects `abk_fido_key_prepare_config()` into the gadget config bind
flow so the `abk_fido` function is added automatically when the USB gadget is
assembled.

这个 patch 会把 `abk_fido_key_prepare_config()` 注入 gadget config bind
流程，在组装 USB gadget 时自动添加 `abk_fido` function。

## Runtime Behavior / 运行期行为

- Adds one extra FIDO HID interface on top of the existing Android composite
  gadget.
- Exposes a misc debug node as `/dev/hidgX` where `X` is usually `0` to `3`.
- Exposes read-only status nodes under `/sys/kernel/abk_fido_key/`:
  `enabled`, `bound`, `udc`, `hid_dev`, `credential_count`, `last_error`,
  `last_trace`, `store_generation`.
- Exposes a write-only reload node under `/sys/kernel/abk_fido_key/reload_store`
  so userspace can force a reload from the metadata blob.
- Exposes a write-only restore trigger under
  `/sys/kernel/abk_fido_key/restore_metadata` so userspace can request a strict
  restore from the persisted store file without streaming the blob through
  sysfs.
- Exposes `/sys/kernel/abk_fido_key/store_blob` as a debug-only binary view of
  the current store; it is not the primary persistence or restore path on
  Android userspace.
- Supports CTAP HID `INIT`, `PING`, `WINK`, `CBOR`, and `CANCEL`.
- Exposes `/dev/abk_fido_ctap` as a transport-independent CTAP HID endpoint for
  the Android Credential Manager provider and the desktop LAN bridge.
- The companion registers as an Android 14+ Credential Manager passkey provider;
  browser requests are translated to CTAP2 and gated by the existing biometric
  approval flow.
- `agent/` contains a Go desktop bridge. Linux creates a `/dev/uhid` virtual
  FIDO HID device; the LAN session uses pairing-code-derived AES-GCM frames.
  Windows keeps the HID backend isolated behind the same interface for a VHID
  service implementation.
- Implements CTAP2 `getInfo`, `makeCredential`, `getAssertion`, `clientPIN`
  (minimal), `reset`, and `selection`.
- Persists the kernel-side FIDO store blob at `/metadata/abk_fido_store.bin`.
- During build injection, the module patches KernelSU SELinux policy setup so
  the `kernel` domain can access that metadata blob without switching SELinux
  to permissive mode.
- The companion app mirrors the active blob into a SQLite database and keeps
  the SQLite mirror in `/metadata/abk_fido.db`.

## Validation / 验证方式

After a successful build and boot, check:

- the driver files were copied into `common/drivers/abk_fido_key`
- `CONFIG_ABK_FIDO_KEY=y` and related symbols are enabled
- `/sys/kernel/abk_fido_key/hid_dev` reports a `hidgX` device name
- `/sys/kernel/abk_fido_key/bound` becomes `1` after the gadget is bound
- `/dev/hidgX` exists for packet-level debugging
- after a credential or PIN change, `/metadata/abk_fido_store.bin` exists
- writing `1` to `/sys/kernel/abk_fido_key/restore_metadata` increments
  `store_generation` and restores the expected `credential_count`
- `/sys/kernel/abk_fido_key/last_error` is empty after a successful restore
- `/sys/kernel/abk_fido_key/last_trace` reports the metadata restore path
- after the companion app sync runs, `/metadata/abk_fido.db` exists

## GitHub Release Automation / GitHub 自动发布

- `.github/workflows/build-companion-app.yml` builds debug and release APKs on
  GitHub Actions.
- The workflow signs the release APK from GitHub secrets, then uses `gh release`
  to create or update the target release and upload
  `abk-fido-companion-release.apk`.
- Required repository secrets:
  `ANDROID_SIGNING_KEYSTORE_BASE64`,
  `ANDROID_SIGNING_KEYSTORE_PASSWORD`,
  `ANDROID_SIGNING_KEY_ALIAS`,
  `ANDROID_SIGNING_KEY_PASSWORD`.
- Pushes to `main` or `master` refresh the rolling `latest` release. Pushing a
  `v*` tag publishes the asset to the matching tagged release.

## Metadata / 元数据

Public module metadata lives in `module.conf` and is intended to match the
published repository. Companion-app metadata is also exported there so ABK can
offer the FIDO SQLite mirror APK alongside the kernel module.

公开模块元数据位于 `module.conf`，并且应与发布后的仓库保持一致。

## Current Limits / 当前边界

- Unsupport Windows Hello
- Windows native HID requires an installed VHID backend; the Go agent's
  transport and protocol are platform independent.

## LAN pairing / 局域网配对

The companion stores a six-to-twelve digit pairing code at
`/metadata/abk_fido_pairing_code` and starts an encrypted TCP listener on port
`38741`. The desktop agent is started with:

```bash
go run ./agent -pairing 123456 -phone 192.168.1.20:38741
```

The code is used as a PSK input to PBKDF2-HMAC-SHA256 and every frame is
authenticated and encrypted with AES-GCM. Do not expose the listener outside a
trusted LAN; rotate the code by deleting the metadata file and restarting the
companion service.
