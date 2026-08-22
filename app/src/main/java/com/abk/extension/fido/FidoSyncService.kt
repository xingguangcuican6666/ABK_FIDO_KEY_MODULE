package com.abk.extension.fido

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
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
    @Volatile
    private var running = false
    @Volatile
    private var syncRequested = true
    @Volatile
    private var syncInFlight = false
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
        lanServer = LanFidoServer(readPairingCode()).also { it.start() }
        startForeground(NOTIFICATION_ID, buildNotification())
        running = true
        Log.i(TAG, "service created")
        thread(name = "abk-fido-service-loop") {
            serviceLoop()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
        if (pending.requestId == lastPromptRequestId || BiometricAuthBridge.isAuthenticating) {
            Log.i(TAG, "skip prompt requestId=${pending.requestId} last=$lastPromptRequestId authing=${BiometricAuthBridge.isAuthenticating}")
            return
        }
        lastPromptRequestId = pending.requestId
        BiometricAuthBridge.begin(pending.requestId)
        Log.i(TAG, "launching auth prompt requestId=${pending.requestId}")
        val launch = RootShell.launchFidoAuthPromptActivity(
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
            true -> FidoKernelBridge.allow(pending.requestId)
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
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle(getString(R.string.service_title))
            .setContentText(getString(R.string.service_text))
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "AbkFidoCompanion"
        const val ACTION_SYNC_NOW = "com.abk.extension.fido.action.SYNC_NOW"
        const val EXTRA_REASON = "reason"
        private const val AUTH_PROMPT_TIMEOUT_MS = 25_000L

        private const val CHANNEL_ID = "abk_fido_companion"
        private const val NOTIFICATION_ID = 1002
    }
}
