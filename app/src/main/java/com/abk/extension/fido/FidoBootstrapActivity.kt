package com.abk.extension.fido

import android.app.Activity
import android.os.Bundle

class FidoBootstrapActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val reason = intent?.getStringExtra(ABK_EXTENSION_EXTRA_ID)?.ifBlank { "bootstrap" }
            ?: "bootstrap"
        FidoSyncService.requestSync(this, reason)
        finish()
    }
}
