# ABK FIDO Key Module

`abk_fido_key_module` is an ABK custom external kernel module that turns an
Android phone build into a composite USB FIDO2 security key.

`abk_fido_key_module` 是一个 ABK 自定义外部内核模块，用来把 Android
手机侧内核扩展成一个复合 USB FIDO2 Security Key。

Current version / 当前版本: `0.3.0`

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
  Windows reaches the same interface through `\\.\ABKFidoVhid`, the control
  device of the `windows/vhid` driver.
- Implements CTAP2 `getInfo`, `makeCredential`, `getAssertion`,
  `getNextAssertion`, `reset`, and `selection`. There is deliberately no
  `clientPIN`: `getInfo` always reports
  `uv: true` and never lists a `clientPin` option, so clients use the phone's
  biometric or screen lock through the companion app instead of asking the user
  to set a separate security-key PIN. `clientPIN` requests are answered with
  `CTAP1_ERR_INVALID_COMMAND`, and a request carrying `pinUvAuthParam` gets
  `CTAP2_ERR_PIN_NOT_SET`.
- Several credentials for one relying party are handled: `getAssertion` reports
  `numberOfCredentials` and the client walks the rest with
  `authenticatorGetNextAssertion` (30 s window, invalidated by any other
  command), each assertion carrying the account's `name` and `displayName`.
- `authenticatorReset` wipes every credential, so it needs the same local
  approval as using a key.
- Local approval is mandatory: nothing that touches a credential is answered
  before the companion app's biometric / screen-lock prompt has been approved,
  and there is no switch that turns that off (`auth_gate_enabled` always reads
  `1` and refuses a `0`). One approval covers further requests for 3 s; a
  refused, cancelled or unanswered prompt instead blocks every request for 3 s.
  `/sys/kernel/abk_fido_key/auth_cooldown` reports both windows.
- Silent requests are refused. A `getAssertion` with the `up` option cleared —
  what browsers use to probe which credential ids exist — would hand out a
  signature with no one in front of the phone, so it gets
  `CTAP2_ERR_UP_REQUIRED` without a prompt and without arming the cooldown.
  `makeCredential` with `up` cleared gets `CTAP2_ERR_INVALID_OPTION`. Exclusion
  is therefore handled the direct way: up to 32 `excludeList` / `allowList`
  entries are parsed per request (`maxCredentialCountInList` advertises 16 to
  stay inside `maxMsgSize`), and a match answers `CTAP2_ERR_CREDENTIAL_EXCLUDED`.
- Persists the kernel-side FIDO store blob at `/metadata/abk_fido_store.bin`.
- During build injection, the module patches KernelSU SELinux policy setup so
  the `kernel` domain can access that metadata blob without switching SELinux
  to permissive mode.
- The companion app mirrors the active blob into a SQLite database and keeps
  the SQLite mirror in `/metadata/abk_fido.db`.
- `FidoSyncService` enforces the app's two switches: with **Use FIDO keys** off
  it answers every pending authorization with a denial, and it only opens the
  LAN listener when both **Use FIDO keys** and **FIDO over Wi‑Fi** are on. USB
  remains the driver's own path and is unaffected by the wireless switch.

## Companion app / 手机应用

`app/` is both the background service and a full app. The launcher entry opens a
single AOSP-style screen (`MainActivity`) that talks to the driver through root;
the foreground service keeps owning root, policy and the biometric prompt, so
closing the app changes nothing about how the key behaves.

`app/` 既是后台服务，也是一个完整应用。桌面图标打开 `MainActivity`
这一个 AOSP 风格页面，通过 root 与驱动交互；前台服务依旧负责 root、
策略与生物识别弹窗，关闭界面不会影响钥匙的行为。

- **Use FIDO keys** is the master switch. The driver's own `enabled` node is
  read-only and local approval can no longer be disabled, so the switch is
  enforced in userspace: the service denies every request while it is off, and
  each denial also starts the driver's 3 s cooldown.
- **FIDO over Wi‑Fi** starts and stops the LAN relay described below.
- **Pairing code** shows the code from `/metadata/abk_fido_pairing_code` and
  copies it to the clipboard.
- **Authorized computers** is the LAN authorization list; a computer stays
  refused until it is authorized here.
- **Registered FIDO keys** lists the occupied slots of
  `/metadata/abk_fido_store.bin`. Each row can be renamed, exported or deleted;
  `Last used` comes from the app's own record of approvals, because the kernel
  store has no room for a timestamp.
- **Import** and **Export all keys** read and write an encrypted `.abkfido`
  file. A slot carries its private key, so the archive is always sealed with
  AES-256-GCM under a PBKDF2-HMAC-SHA256 passphrase (210 000 iterations, the
  plaintext header as associated data).
- Keys cannot be created from the app: a credential is minted by the site that
  asks for one. **Add FIDO key** says so and offers the import path.

Every edit rewrites the blob, resets magic, version and CRC-32 over
`sign_count`..end, writes `1` to `restore_metadata`, and only reports success
once `store_generation` has advanced and `credential_count` matches. A blob the
driver rejects therefore surfaces as a failure instead of a silent no-op.

## Validation / 验证方式

After a successful build and boot, check:

- the driver files were copied into `common/drivers/abk_fido_key`
- `CONFIG_ABK_FIDO_KEY=y` and related symbols are enabled
- `/sys/kernel/abk_fido_key/hid_dev` reports a `hidgX` device name
- `/sys/kernel/abk_fido_key/bound` becomes `1` after the gadget is bound
- `/dev/hidgX` exists for packet-level debugging
- after a credential change, `/metadata/abk_fido_store.bin` exists
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

- Windows Hello is supported on the USB path, including offline hmac-secret
  unlock. The device selection ceremony is handled — Windows
  sends a makeCredential with `rp.id` = `user.name` = `"SelectDevice"` (built in
  `_SelectDevice`, `webauthnctap.cpp`) and the driver answers it like Chromium's
  `.dummy` request: collect the local approval, return a throwaway
  makeCredential response, create nothing.
- The LAN relay needs a virtual HID device on the desktop, and creating one is
  privileged on both platforms: on Linux the agent uses `/dev/uhid` and must run
  as root; on Windows it needs the `abkfidovhid` driver from
  [Windows virtual HID driver](#windows-virtual-hid-driver--windows-虚拟-hid-驱动)
  installed and must run elevated. That driver is self-signed here, so the
  machine has to have test signing on (which means Secure Boot off) — if that is
  not acceptable, connect the phone over USB instead, where the gadget is a
  native FIDO HID key that needs no driver.
  局域网中转在 Windows 上需要安装本仓库的 `abkfidovhid` 虚拟 HID 驱动，并开启测试签名
  （需关闭安全启动）；若不便如此，请改用 USB 连接手机。

## Windows virtual HID driver / Windows 虚拟 HID 驱动

Windows WebAuthn only enumerates real HID devices, so `windows/` contains the
driver that gives the LAN relay something for browsers to find:

- `windows/vhid/` — `abkfidovhid.sys`, a KMDF function driver built on the
  Virtual HID Framework (`vhf.sys` is added as a lower filter). It publishes a
  CTAP HID device (usage page `0xF1D0`, 64-byte input and output reports) and
  the control device `\\.\ABKFidoVhid`, whose security descriptor admits only
  SYSTEM and Administrators. The WDK comes from the NuGet packages pinned in
  `packages.config`, so no machine-wide WDK install is required.
- `windows/tools/abkvhidctl/` — `abkvhidctl.exe`, which creates, inspects and
  removes the root-enumerated devnode the driver binds to (`abkvhidctl install
  <inf>` / `remove` / `status`). `pnputil` cannot invent a devnode for hardware
  that does not exist, which is what a software-only HID source needs.
  `abkvhidctl loopback` additionally plays both host and key — it writes an
  output report into the HID interface Windows published and answers it through
  `\\.\ABKFidoVhid` — so whether a CTAP frame survives each direction of the
  driver is answered without the phone, the relay or `webauthn.dll` taking part.
  It needs the agent stopped, since both want the same exclusive handle, and it
  tries the reply with and without a leading report id byte, leaving the driver
  set to whichever shape came back.
- `windows/scripts/` — `Sign-Package.ps1` (packages and test-signs with a
  freshly generated self-signed certificate), plus
  `Install-AbkFidoVhid.ps1` / `Uninstall-AbkFidoVhid.ps1`.

`.github/workflows/build-windows-vhid.yml` builds and test-signs all of it on
`windows-latest` and uploads the `abk-fido-vhid-x64` artifact. To install, from
an elevated PowerShell prompt in the extracted artifact:

```powershell
.\Install-AbkFidoVhid.ps1 -EnableTestSigning   # reboot, then run it again
.\abkvhidctl.exe status
```

The certificate is generated on the machine that runs the build, so a
self-signed package will only load while test signing is on; the installer
checks Secure Boot and the test-signing flag and reports what is missing instead
of changing boot configuration on its own. Devnode problem code 52 means the
signature was rejected. Then run the agent elevated, as usual:

```powershell
sudo .\abk-fido-agent-windows-amd64.exe
```

To back it all out: `.\Uninstall-AbkFidoVhid.ps1 -RemoveDriverPackage
-RemoveCertificate`, then `bcdedit /set testsigning off`.


## LAN pairing / 局域网配对

The companion stores a six-to-twelve digit pairing code at
`/metadata/abk_fido_pairing_code` and starts an encrypted TCP listener on port
`38741`. The desktop agent discovers phones automatically when `-phone` is
omitted, lets the user choose a discovered device, and asks that phone to show
the pairing code in a confirmation window:

```bash
go run ./agent
```

For scripted use, the explicit form remains supported:

```bash
go run ./agent -pairing 123456 -phone 192.168.1.20:38741
```

The code is used as a PSK input to PBKDF2-HMAC-SHA256 and every frame is
authenticated and encrypted with AES-GCM. Do not expose the listener outside a
trusted LAN; rotate the code by deleting the metadata file and restarting the
companion service.

### Authorizing a computer / 授权电脑

The pairing code only protects the transport, so the phone also keeps a list of
the machines allowed to use the key. Right after the handshake the agent names
itself with `{"t":"hello","id":…,"name":…,"os":…}`, where `id` is 16 random bytes
generated once and kept in `<user config dir>/abk-fido/client-id`, and the phone
replies with `{"t":"hello-ack","status":…}`:

配对码只保护传输，因此手机还维护一份可以使用钥匙的电脑列表。

- `authorized` — the session proceeds and CTAP traffic starts.
- `pending` — a new computer. The phone posts a notification; open **Authorized
  computers** in the app and allow it. The agent logs what to do and retries
  every 5 s. Turning on **Authorize new computers automatically** on that screen
  skips the prompt.
- `blocked` — the computer was blocked in the app; the agent backs off to 30 s.

Every session re-checks on hello, so revoking a computer takes effect on its
next connection. An agent talking to a phone build that predates the handshake
sees the session closed during hello and is told to update the app.
