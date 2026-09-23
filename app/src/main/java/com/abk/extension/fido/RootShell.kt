package com.abk.extension.fido

import com.topjohnwu.superuser.Shell

internal object RootShell {
    data class CommandResult(
        val exitCode: Int,
        val stdout: String,
    ) {
        val success: Boolean
            get() = exitCode == 0
    }

    @Volatile
    private var initialized = false
    private val initLock = Any()

    fun init() {
        if (initialized) return
        synchronized(initLock) {
            if (initialized) return
            Shell.enableVerboseLogging = false
            Shell.setDefaultBuilder(
                Shell.Builder.create()
                    .setFlags(Shell.FLAG_MOUNT_MASTER or Shell.FLAG_REDIRECT_STDERR)
                    .setTimeout(10)
            )
            initialized = true
        }
    }

    fun isRootAvailable(): Boolean {
        val result = run("id -u")
        return result.success && result.stdout.trim() == "0"
    }

    fun readFileBase64(path: String): CommandResult {
        return run(
            """
            file=${shellQuote(path)}
            [ -f "${'$'}file" ] || exit 3
            base64 "${'$'}file" 2>/dev/null | tr -d '\n'
            """.trimIndent()
        )
    }

    fun readTextFile(path: String): CommandResult {
        return run(
            """
            file=${shellQuote(path)}
            [ -f "${'$'}file" ] || exit 3
            cat "${'$'}file"
            """.trimIndent()
        )
    }

    fun ensureEmptyFileIfMissing(path: String): CommandResult {
        return run(
            """
            set -e
            dst=${shellQuote(path)}
            if [ -e "${'$'}dst" ]; then
                printf 'exists'
            else
                parent=$(dirname "${'$'}dst")
                mkdir -p "${'$'}parent"
                touch "${'$'}dst"
                chmod 0600 "${'$'}dst" 2>/dev/null || true
                restorecon "${'$'}dst" 2>/dev/null || true
                printf 'created'
            fi
            """.trimIndent()
        )
    }

    fun writeTextFile(path: String, payload: String): CommandResult {
        return run(
            """
            set -e
            dst=${shellQuote(path)}
            printf '%s' ${shellQuote(payload)} > "${'$'}dst"
            """.trimIndent()
        )
    }

    fun writeFileBase64(path: String, payloadBase64: String): CommandResult {
        return run(
            """
            set -e
            dst=${shellQuote(path)}
            printf '%s' ${shellQuote(payloadBase64)} | base64 -d > "${'$'}dst"
            chmod 0600 "${'$'}dst" 2>/dev/null || true
            restorecon "${'$'}dst" 2>/dev/null || true
            """.trimIndent()
        )
    }

    /**
     * The kernel CTAP endpoint accepts exactly one [DEVICE_PACKET_LEN]-byte
     * write per packet and returns EINVAL for any other length, so piping the
     * decoder straight into the device makes success depend on how base64
     * happens to flush its output. Stage the packet in a temp file, check the
     * decoded length, and let dd issue a single fixed-size write.
     *
     * The script must never call `exit`: that ends the shell before libsu can
     * read the job's completion marker, which reports even a successful write
     * as a failure. The trailing test carries the status instead.
     */
    fun writeDeviceBase64(path: String, payloadBase64: String): CommandResult = run(
        """
        tmp=/data/local/tmp/.abk_fido_tx.${'$'}${'$'}
        status=0
        if printf '%s' ${shellQuote(payloadBase64)} | base64 -d > "${'$'}tmp"; then
            size=${'$'}(wc -c < "${'$'}tmp" | tr -d ' ')
            if [ "${'$'}size" = '$DEVICE_PACKET_LEN' ]; then
                if ! dd if="${'$'}tmp" of=${shellQuote(path)} bs=$DEVICE_PACKET_LEN count=1 2>/dev/null; then
                    echo 'device rejected the packet'
                    status=6
                fi
            else
                echo "decoded ${'$'}size bytes, expected $DEVICE_PACKET_LEN"
                status=5
            fi
        else
            echo 'base64 decode failed'
            status=4
        fi
        rm -f "${'$'}tmp"
        [ "${'$'}status" = 0 ]
        """.trimIndent(),
        timeoutSeconds = 40L,
    )

    fun readDeviceBase64(path: String, count: Int, timeoutSeconds: Long): CommandResult = run(
        // Keep the child command cancellable as well as the libsu job. A
        // plain blocking dd can survive a Java thread interrupt and become a
        // stale reader of the shared CTAP TX queue.
        "set -o pipefail; timeout ${timeoutSeconds}s dd if=${shellQuote(path)} bs=$count count=1 2>/dev/null | base64",
        timeoutSeconds + 2,
    )

    fun copyFileToMetadata(srcPath: String, dstPath: String): CommandResult {
        return run(
            """
            src=${shellQuote(srcPath)}
            dst=${shellQuote(dstPath)}
            [ -f "${'$'}src" ] || exit 3
            cp -f "${'$'}src" "${'$'}dst"
            chmod 0600 "${'$'}dst" 2>/dev/null || true
            restorecon "${'$'}dst" 2>/dev/null || true
            """.trimIndent()
        )
    }

    fun copyFileFromMetadata(srcPath: String, dstPath: String, ownerUid: Int): CommandResult {
        return run(
            """
            src=${shellQuote(srcPath)}
            dst=${shellQuote(dstPath)}
            [ -f "${'$'}src" ] || exit 3
            cp -f "${'$'}src" "${'$'}dst"
            chown ${ownerUid}:${ownerUid} "${'$'}dst" 2>/dev/null || true
            chmod 0600 "${'$'}dst" 2>/dev/null || true
            """.trimIndent()
        )
    }

    fun launchAbkExtensionManager(): CommandResult {
        return run(
            """
            am start -n 'com.abk.kernel/com.abk.kernel.extensions.AbkExtensionManagerActivity' \
              --es 'com.abk.kernel.extra.EXTENSION_ID' 'abk_fido_store' \
              --ez 'bootstrap_mode' 'true'
            """.trimIndent()
        )
    }

    fun launchFidoAuthPromptActivity(
        packageName: String,
        requestId: Int,
        command: String,
        rpId: String,
    ): CommandResult {
        // The activity class always lives in the com.abk.extension.fido
        // namespace, but the running package carries the build's applicationId
        // (e.g. the .debug suffix), so the component must be built from the
        // caller's own package with the fully-qualified class name rather than
        // the ".FidoAuthPromptActivity" shorthand.
        val component = "$packageName/com.abk.extension.fido.FidoAuthPromptActivity"
        return run(
            """
            am start -n ${shellQuote(component)} \
              --ei 'request_id' ${requestId} \
              --es 'command' ${shellQuote(command)} \
              --es 'rp_id' ${shellQuote(rpId)}
            """.trimIndent()
        )
    }

    fun launchPairingCodeActivity(): CommandResult {
        return run(
            """
            am start -W -n 'com.abk.extension.fido/.PairingCodeActivity' \
              -a android.intent.action.MAIN \
              -f 0x10200000
            """.trimIndent()
        )
    }

    fun run(script: String, timeoutSeconds: Long = 10L): CommandResult {
        init()
        return try {
            val output = mutableListOf<String>()
            val result = createRootShell(timeoutSeconds = timeoutSeconds).use { shell ->
                shell.newJob()
                    .to(output, output)
                    .add(script)
                    .exec()
            }
            CommandResult(
                exitCode = if (result.isSuccess) 0 else 1,
                stdout = output.joinToString("\n")
            )
        } catch (t: Throwable) {
            CommandResult(exitCode = 127, stdout = t.message.orEmpty())
        }
    }

    private fun createRootShell(timeoutSeconds: Long): Shell {
        val builder = Shell.Builder.create()
            .setFlags(Shell.FLAG_MOUNT_MASTER or Shell.FLAG_REDIRECT_STDERR)
            .setTimeout(timeoutSeconds)
        val candidates = arrayOf(
            arrayOf("/data/adb/ksud", "debug", "su", "-g"),
            arrayOf("ksud", "debug", "su", "-g"),
            arrayOf("su", "-mm"),
            arrayOf("su")
        )
        candidates.forEach { command ->
            try {
                val shell = builder.build(*command)
                if (isShellRoot(shell)) return shell
                shell.close()
            } catch (_: Throwable) {
            }
        }

        val shell = builder.build()
        if (isShellRoot(shell)) return shell
        shell.close()
        throw IllegalStateException("Root shell unavailable")
    }

    private fun isShellRoot(shell: Shell): Boolean {
        val output = mutableListOf<String>()
        val result = shell.newJob()
            .to(output, output)
            .add("id -u")
            .exec()
        return result.isSuccess && output.firstOrNull()?.trim() == "0"
    }

    private fun shellQuote(value: String): String {
        return "'" + value.replace("'", "'\\''") + "'"
    }

    /** Fixed CTAP HID report size the kernel endpoint accepts per write. */
    private const val DEVICE_PACKET_LEN = 64
}
