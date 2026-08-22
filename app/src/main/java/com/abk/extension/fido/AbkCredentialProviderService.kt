package com.abk.extension.fido

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry

class AbkCredentialProviderService : CredentialProviderService() {
    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val entries = request.beginGetCredentialOptions
            .filterIsInstance<BeginGetPublicKeyCredentialOption>()
            .mapIndexed { index, option ->
                PublicKeyCredentialEntry(
                    context = this,
                    username = getString(R.string.app_name),
                    displayName = option.requestJson.rpIdOrFallback(),
                    pendingIntent = activityIntent(1000 + index),
                    beginGetPublicKeyCredentialOption = option,
                )
            }
        callback.onResult(BeginGetCredentialResponse.Builder().setCredentialEntries(entries).build())
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request.type != PublicKeyCredential.TYPE_PUBLIC_KEY_CREDENTIAL) {
            callback.onError(CreateCredentialUnknownException("Unsupported credential type"))
            return
        }
        callback.onResult(
            BeginCreateCredentialResponse.Builder().addCreateEntry(
                CreateEntry(
                    accountName = getString(R.string.app_name),
                    pendingIntent = activityIntent(2000),
                    description = "ABK kernel FIDO authenticator",
                )
            ).build()
        )
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) = callback.onResult(null)

    private fun activityIntent(requestCode: Int): PendingIntent = PendingIntent.getActivity(
        this,
        requestCode,
        Intent(this, CredentialProviderActivity::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
    )

    private fun String.rpIdOrFallback(): String = runCatching {
        org.json.JSONObject(this).optString("rpId").ifBlank { getString(R.string.app_name) }
    }.getOrDefault(getString(R.string.app_name))
}
