package com.abk.extension.fido

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationCompat
import kotlin.concurrent.thread
import java.security.SecureRandom

class FidoSyncService : Service() {
    private var lanServer: LanFidoServer? = null
    private lateinit var settings: FidoSettings
    private lateinit var clients: LanClientRegistry
    @Volatile
    private var running = false
    @Volatile
    private var syncRequested = true
    @Volatile
    private var syncInFlight = false
    @Volatile
    private var policyRequested = true
    @Volatile
    private var lastSyncReason = "service_start"
    @Volatile
    private var lastPromptRequestId = -1
    @Volatile
    private var lastObservedStoreGeneration = -1
    private val syncStateLock = Any()

    override fun onCreate() {
        super.onCreate()
        RootShell.init()
        settings = FidoSettings.of(this)
        clients = LanClientRegistry.of(this)
        startForeground(NOTIFICATION_ID, buildNotification())
        running = true
        Log.i(TAG, "service created")
        thread(name = "abk-fido-service-loop") {
            serviceLoop()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_APPLY_POLICY) {
            policyRequested = true
            Log.i(TAG, "policy change requested")
            return START_STICKY
        }
        lastSyncReason = intent?.getStringExtra(EXTRA_REASON)
            ?: intent?.action
            ?: "service_restart"
        syncRequested = true
        Log.i(TAG, "onStartCommand reason=$lastSyncReason")
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        lanServer?.stop()
        Log.i(TAG, "service destroyed")
        super.onDestroy()
    }

    private fun readPairingCode(): String {
        val path = "/metadata/abk_fido_pairing_code"
        val existing = RootShell.readTextFile(path).stdout.trim()
        if (existing.matches(Regex("[0-9]{6,12}"))) return existing
        val generated = (100000 + SecureRandom().nextInt(900000)).toString()
        RootShell.writeTextFile(path, generated + "\n")
        return generated
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun serviceLoop() {
        while (running) {
            runCatching {
                reconcilePolicyIfNeeded()
            }.onFailure {
                Log.w(TAG, "policy reconcile failed", it)
            }

            runCatching {
                maybeHandlePendingAuth()
            }.onFailure {
                Log.w("AbkFidoCompanion", "auth loop failed", it)
            }

            runCatching {
                maybeScheduleStoreSync()
            }.onFailure {
                Log.w(TAG, "store generation poll failed", it)
            }

            kickSyncIfNeeded()

            try {
                Thread.sleep(750)
            } catch (_: InterruptedException) {
                break
            }
        }
    }

    /**
     * Bring the relay and the driver's decision gate in line with the switches
     * in the app. This runs on the service thread because both need root, which
     * must not be waited on from the main thread.
     */
    private fun reconcilePolicyIfNeeded() {
        if (!policyRequested) return
        policyRequested = false

        val relayWanted = settings.fidoEnabled && settings.wirelessEnabled
        val current = lanServer
        if (relayWanted && current == null) {
            lanServer = LanFidoServer(
                pairingCode = readPairingCode(),
                registry = clients,
                settings = settings,
                listener = pendingClientListener,
            ).also { it.start() }
            Log.i(TAG, "LAN relay started")
        } else if (!relayWanted && current != null) {
            current.stop()
            lanServer = null
            Log.i(TAG, "LAN relay stopped")
        }

        // The driver's own `enabled` node is read-only, so the master switch is
        // enforced here: the gate stays on and this service answers every
        // request, denying while the switch is off.
        if (FidoKernelBridge.readAuthGateEnabled() == false) {
            val gate = FidoKernelBridge.writeAuthGateEnabled(true)
            if (!gate.success) Log.w(TAG, "enabling auth_gate failed: ${gate.stdout.trim()}")
        }
    }

    private val pendingClientListener = object : LanFidoServer.Listener {
        override fun onClientPending(record: LanClientRecord) {
            notifyPendingClient(record)
        }
    }

    private fun notifyPendingClient(record: LanClientRecord) {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    ALERT_CHANNEL_ID,
                    getString(R.string.alert_channel_name),
                    NotificationManager.IMPORTANCE_DEFAULT
                )
            )
        }
        val intent = Intent(this, LanClientsActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pending = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(getString(R.string.alert_pending_client_title))
            .setContentText(getString(R.string.alert_pending_client_text, record.displayName(this)))
            .setContentIntent(pending)
            .setAutoCancel(true)
            .build()
        runCatching { manager.notify(ALERT_NOTIFICATION_ID, notification) }
    }

    private fun maybeScheduleStoreSync() {
        val generation = FidoKernelBridge.readStoreGeneration() ?: return
        if (lastObservedStoreGeneration == -1) {
            lastObservedStoreGeneration = generation
            return
        }
        if (generation == lastObservedStoreGeneration) {
            return
        }
        lastObservedStoreGeneration = generation
        synchronized(syncStateLock) {
            syncRequested = true
            lastSyncReason = "store_generation_$generation"
        }
        Log.i(TAG, "detected store generation change=$generation")
    }

    private fun kickSyncIfNeeded() {
        var reason = ""
        synchronized(syncStateLock) {
            if (!syncRequested || syncInFlight) {
                return
            }
            syncRequested = false
            syncInFlight = true
            reason = lastSyncReason
        }
        thread(name = "abk-fido-sync") {
            try {
                Log.i(TAG, "running sync reason=$reason")
                val result = MetadataSyncCoordinator(applicationContext).syncNow(reason)
                publishState(result, reason)
            } finally {
                synchronized(syncStateLock) {
                    syncInFlight = false
                }
            }
        }
    }

    private fun maybeHandlePendingAuth() {
        val pending = FidoKernelBridge.readPendingAuthRequest() ?: return
        Log.i(TAG, "pending auth requestId=${pending.requestId} cmd=${pending.command} rp=${pending.rpId} uv=${pending.uv} rk=${pending.rk}")
        if (!settings.fidoEnabled) {
            // The master switch is off, so nothing is asked of the user: the
            // request is refused and the browser sees a declined operation.
            Log.i(TAG, "denying requestId=${pending.requestId}: FIDO is switched off")
            FidoKernelBridge.deny(pending.requestId)
            return
        }
        if (pending.requestId == lastPromptRequestId || BiometricAuthBridge.isAuthenticating) {
            Log.i(TAG, "skip prompt requestId=${pending.requestId} last=$lastPromptRequestId authing=${BiometricAuthBridge.isAuthenticating}")
            return
        }
        lastPromptRequestId = pending.requestId
        BiometricAuthBridge.begin(pending.requestId)
        Log.i(TAG, "launching auth prompt requestId=${pending.requestId}")
        val launch = RootShell.launchFidoAuthPromptActivity(
            packageName = packageName,
            requestId = pending.requestId,
            command = pending.command,
            rpId = pending.rpId
        )
        if (!launch.success) {
            Log.w(TAG, "failed to launch auth prompt requestId=${pending.requestId} output=${launch.stdout}")
            Handler(Looper.getMainLooper()).post {
                Toast.makeText(
                    this,
                    getString(R.string.auth_prompt_launch_failed),
                    Toast.LENGTH_SHORT
                ).show()
            }
            FidoKernelBridge.deny(pending.requestId)
            RootShell.launchAbkExtensionManager()
            BiometricAuthBridge.finish(false)
            return
        }

        val result = BiometricAuthBridge.await(AUTH_PROMPT_TIMEOUT_MS)
        Log.i(TAG, "auth result requestId=${pending.requestId} result=${result?.toString() ?: "timeout"}")
        when (result) {
            true -> {
                FidoKernelBridge.allow(pending.requestId)
                // The store has nowhere to keep a timestamp, so the key list
                // gets its "last used" line from here.
                settings.recordUsed(pending.rpId)
            }
            false -> FidoKernelBridge.deny(pending.requestId)
            null -> {
                FidoKernelBridge.deny(pending.requestId)
                RootShell.launchAbkExtensionManager()
            }
        }
    }

    private fun publishState(result: SyncResult, reason: String) {
        Log.i(TAG, "publishState success=${result.success} reason=$reason message=${result.userMessage(this)}")
        runCatching {
            HostBridge(
                resolver = contentResolver,
                authority = ABK_EXTENSION_DEFAULT_HOST_PROVIDER,
                extensionId = ABK_EXTENSION_DEFAULT_ID
            ).writeState(
                summary = result.userMessage(this),
                success = result.success,
                reason = reason
            )
        }
    }

    private fun buildNotification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.service_channel_name),
                    NotificationManager.IMPORTANCE_MIN
                )
            )
        }
        val open = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle(getString(R.string.service_title))
            .setContentText(getString(R.string.service_text))
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "AbkFidoCompanion"
        const val ACTION_SYNC_NOW = "com.abk.extension.fido.action.SYNC_NOW"
        const val ACTION_APPLY_POLICY = "com.abk.extension.fido.action.APPLY_POLICY"
        const val EXTRA_REASON = "reason"
        private const val AUTH_PROMPT_TIMEOUT_MS = 25_000L

        private const val CHANNEL_ID = "abk_fido_companion"
        private const val NOTIFICATION_ID = 1002
        private const val ALERT_CHANNEL_ID = "abk_fido_alerts"
        private const val ALERT_NOTIFICATION_ID = 1003

        /** Ask the running service to re-read the switches in [FidoSettings]. */
        fun applyPolicy(context: Context) {
            val intent = Intent(context, FidoSyncService::class.java).apply {
                action = ACTION_APPLY_POLICY
            }
            startGuarded(context, intent)
        }

        /** Ask the running service to sync the store to persistent storage. */
        fun requestSync(context: Context, reason: String) {
            val intent = Intent(context, FidoSyncService::class.java).apply {
                action = ACTION_SYNC_NOW
                putExtra(EXTRA_REASON, reason)
            }
            startGuarded(context, intent)
        }

        /**
         * Start the service, tolerating the Android 12+ background
         * foreground-service-start restriction. Every trigger that can fire
         * while the process has no foreground standing funnels through here: a
         * boot / user-unlock / package-replaced broadcast (SyncTriggerReceiver),
         * the keep-alive job, and the provider's own cold-start init
         * (FidoInitProvider). In those contexts startForegroundService() throws
         * ForegroundServiceStartNotAllowedException, and that is fatal inside a
         * BroadcastReceiver or ContentProvider — it kills the whole process
         * before the Credential Manager ceremony can run, surfacing to the
         * browser as a generic "unknown error". Swallow it: the ceremony starts
         * the service from the foreground CredentialProviderActivity, where the
         * start is allowed, and the keep-alive job catches up on every other
         * trigger.
         */
        private fun startGuarded(context: Context, intent: Intent) {
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            }.onFailure { Log.w(TAG, "service start skipped (${intent.action}): ${it.message}") }
        }
    }
}
