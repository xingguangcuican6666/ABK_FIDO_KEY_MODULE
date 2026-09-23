package com.abk.extension.fido

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class SyncTriggerReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        FidoKeepAliveJobService.schedule(context)
        // Boot, user-unlock and package-replaced broadcasts arrive while the app
        // sits in the background, where startForegroundService() is disallowed;
        // throwing here would crash the receiver's process. requestSync swallows
        // that failure, and the keep-alive job scheduled above starts the service
        // once the constraints allow it.
        FidoSyncService.requestSync(context, intent?.action ?: "broadcast")
    }
}
