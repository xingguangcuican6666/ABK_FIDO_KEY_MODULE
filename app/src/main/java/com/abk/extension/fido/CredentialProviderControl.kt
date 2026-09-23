package com.abk.extension.fido

import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.provider.Settings

/**
 * Reads and, with root, changes which app the system hands passkey / FIDO
 * requests to.
 *
 * Android 14+ Credential Manager keeps its enabled providers in two secure
 * settings: [KEY_ENABLED] is the colon-separated list of providers the user has
 * turned on, and [KEY_PRIMARY] is the single one used as the default when a site
 * asks to create a passkey. The system Settings UI writes both, and the
 * framework's CredentialManagerService observes them, so a root `settings put`
 * is the very same switch the user would make by hand — we just make it from
 * here. Reads need neither root nor a permission; only the switch does.
 */
internal object CredentialProviderControl {

    /** Colon-separated list of the credential-provider components the user enabled. */
    private const val KEY_ENABLED = "credential_service"

    /** The single preferred provider, used as the default for creating passkeys. */
    private const val KEY_PRIMARY = "credential_service_primary"

    data class Status(
        /** Our service is in the enabled list, so it takes part in ceremonies. */
        val enabled: Boolean,
        /** Our service is the preferred provider. */
        val preferred: Boolean,
        /** Label of whoever is preferred right now, when it is not us. */
        val otherPreferredLabel: String?,
    )

    /** Credential Manager only exists on Android 14+ (API 34). */
    val supported: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE

    fun component(context: Context): String =
        ComponentName(context, AbkCredentialProviderService::class.java).flattenToString()

    fun read(context: Context): Status {
        val ours = component(context)
        val enabled = readSetting(context, KEY_ENABLED).splitComponents()
        val primary = readSetting(context, KEY_PRIMARY).trim()
        val preferred = primary == ours
        return Status(
            enabled = enabled.any { it == ours },
            preferred = preferred,
            otherPreferredLabel = if (preferred || primary.isBlank()) null else labelOf(context, primary),
        )
    }

    /**
     * Add ourselves to the enabled providers and become the preferred one,
     * remembering the provider we displaced so [restore] can put it back.
     * Returns false when the writes could not be made (root is required).
     */
    fun enableAsPreferred(context: Context): Boolean {
        val ours = component(context)
        val enabled = readSetting(context, KEY_ENABLED).splitComponents().toMutableList()
        if (enabled.none { it == ours }) enabled += ours
        val previousPrimary = readSetting(context, KEY_PRIMARY).trim()
        if (previousPrimary.isNotBlank() && previousPrimary != ours) {
            FidoSettings.of(context).previousCredentialPrimary = previousPrimary
        }
        return putSettings(
            KEY_ENABLED to enabled.joinToString(":"),
            KEY_PRIMARY to ours,
        )
    }

    /**
     * Take ourselves back out of the enabled providers and hand the preferred
     * slot back to whoever held it before [enableAsPreferred] ran. If the user
     * has since chosen a different preferred provider by hand, that choice is
     * left untouched. Returns false when the writes could not be made.
     */
    fun restore(context: Context): Boolean {
        val ours = component(context)
        val enabled = readSetting(context, KEY_ENABLED).splitComponents().filterNot { it == ours }
        val primary = readSetting(context, KEY_PRIMARY).trim()
        val settings = FidoSettings.of(context)
        val restoredPrimary = when {
            primary != ours -> primary // the user already moved it; do not fight them
            else -> settings.previousCredentialPrimary ?: enabled.firstOrNull() ?: ""
        }
        val ok = putSettings(
            KEY_ENABLED to enabled.joinToString(":"),
            KEY_PRIMARY to restoredPrimary,
        )
        if (ok) settings.previousCredentialPrimary = null
        return ok
    }

    private fun readSetting(context: Context, key: String): String {
        // A plain read needs no permission and no root; fall back to root only
        // if the platform hides the value from a normal app.
        runCatching {
            Settings.Secure.getString(context.contentResolver, key)
        }.getOrNull()?.let { return it }
        val result = RootShell.run("settings get secure $key")
        if (!result.success) return ""
        return result.stdout.trim().let { if (it == "null") "" else it }
    }

    private fun putSettings(vararg pairs: Pair<String, String>): Boolean {
        val script = pairs.joinToString("\n") { (key, value) ->
            "settings put secure $key '${value.replace("'", "'\\''")}'"
        }
        return RootShell.run(script).success
    }

    private fun String.splitComponents(): List<String> =
        split(":").map { it.trim() }.filter { it.isNotEmpty() }

    private fun labelOf(context: Context, flattened: String): String {
        val component = ComponentName.unflattenFromString(flattened) ?: return flattened
        return runCatching {
            val pm = context.packageManager
            pm.getApplicationLabel(pm.getApplicationInfo(component.packageName, 0)).toString()
        }.getOrNull() ?: component.packageName
    }
}
