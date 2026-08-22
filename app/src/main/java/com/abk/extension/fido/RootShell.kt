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
                exit 0
            fi
            parent=$(dirname "${'$'}dst")
            mkdir -p "${'$'}parent"
            touch "${'$'}dst"
            chmod 0600 "${'$'}dst" 2>/dev/null || true
            restorecon "${'$'}dst" 2>/dev/null || true
            printf 'created'
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

    fun writeDeviceBase64(path: String, payloadBase64: String): CommandResult = run(
        "printf '%s' ${shellQuote(payloadBase64)} | base64 -d > ${shellQuote(path)}",
        timeoutSeconds = 40L,
    )

    fun readDeviceBase64(path: String, count: Int, timeoutSeconds: Long): CommandResult = run(
        "dd if=${shellQuote(path)} bs=$count count=1 2>/dev/null | base64 | tr -d '\\n'",
        timeoutSeconds,
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
        requestId: Int,
        command: String,
        rpId: String,
    ): CommandResult {
        return run(
            """
            am start -n 'com.abk.extension.fido/.FidoAuthPromptActivity' \
              --ei 'request_id' ${requestId} \
              --es 'command' ${shellQuote(command)} \
              --es 'rp_id' ${shellQuote(rpId)}
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
}
