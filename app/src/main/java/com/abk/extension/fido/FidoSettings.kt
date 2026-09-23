package com.abk.extension.fido

import android.content.Context
import android.content.SharedPreferences

/**
 * User-facing policy for the FIDO key, plus the small facts the UI needs and the
 * kernel does not keep.
 *
 * The preferences live in device-protected storage because [FidoSyncService]
 * starts before the user unlocks the device and has to know whether the key is
 * meant to answer at all.
 */
internal class FidoSettings private constructor(private val prefs: SharedPreferences) {

    var fidoEnabled: Boolean
        get() = prefs.getBoolean(KEY_FIDO_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_FIDO_ENABLED, value).apply()

    /** The LAN relay, i.e. answering CTAP over Wi-Fi for a desktop agent. */
    var wirelessEnabled: Boolean
        get() = prefs.getBoolean(KEY_WIRELESS_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_WIRELESS_ENABLED, value).apply()

    /**
     * Whether a desktop that presents the pairing code for the first time is
     * authorized straight away. Off by default: knowing the code should not be
     * enough to make the key usable from an unfamiliar machine.
     */
    var autoAuthorizeNewClients: Boolean
        get() = prefs.getBoolean(KEY_AUTO_AUTHORIZE, false)
        set(value) = prefs.edit().putBoolean(KEY_AUTO_AUTHORIZE, value).apply()

    /**
     * The credential provider that was the system default before we took the
     * preferred slot, so it can be handed back when the user switches away.
     * Null once there is nothing to restore.
     */
    var previousCredentialPrimary: String?
        get() = prefs.getString(KEY_PREV_PRIMARY, null)
        set(value) = prefs.edit().apply {
            if (value.isNullOrBlank()) remove(KEY_PREV_PRIMARY) else putString(KEY_PREV_PRIMARY, value)
        }.apply()

    /**
     * Last time a credential of [rpId] was used. The kernel store has no room
     * for a timestamp, so the approval path records it here instead.
     */
    fun lastUsed(rpId: String): Long = prefs.getLong(lastUsedKey(rpId), 0L)

    fun recordUsed(rpId: String, atMillis: Long = System.currentTimeMillis()) {
        if (rpId.isBlank()) return
        prefs.edit().putLong(lastUsedKey(rpId), atMillis).apply()
    }

    fun forgetUsage(rpId: String) {
        prefs.edit().remove(lastUsedKey(rpId)).apply()
    }

    internal fun rawPreferences(): SharedPreferences = prefs

    private fun lastUsedKey(rpId: String) = KEY_LAST_USED_PREFIX + rpId

    companion object {
        private const val PREFS_NAME = "abk_fido_settings"
        private const val KEY_FIDO_ENABLED = "fido_enabled"
        private const val KEY_WIRELESS_ENABLED = "wireless_enabled"
        private const val KEY_AUTO_AUTHORIZE = "lan_auto_authorize"
        private const val KEY_PREV_PRIMARY = "prev_credential_primary"
        private const val KEY_LAST_USED_PREFIX = "last_used_rp_"

        fun of(context: Context): FidoSettings {
            val deviceContext = context.applicationContext.createDeviceProtectedStorageContext()
            return FidoSettings(deviceContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE))
        }
    }
}
