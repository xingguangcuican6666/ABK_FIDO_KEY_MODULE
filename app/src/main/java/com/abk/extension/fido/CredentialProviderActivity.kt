package com.abk.extension.fido

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.CreatePublicKeyCredentialResponse
import kotlin.concurrent.thread

class CredentialProviderActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The driver blocks each makeCredential/getAssertion on a local
        // approval, and the biometric prompt for that gate is raised by
        // FidoSyncService. When the system cold-starts this provider process in
        // the background, FidoInitProvider cannot start that foreground service
        // (background start is disallowed), so start it here: this activity is
        // a foreground context, where the start is permitted. Defensive so a
        // start failure never crashes the ceremony.
        runCatching { FidoSyncService.requestSync(this, "credential_provider") }
            .onFailure { Log.w(TAG, "could not start sync service for ceremony: ${it.message}") }
        thread(name = "abk-credential-provider") { finishProviderRequest() }
    }

    private fun finishProviderRequest() {
        val allowlist = runCatching {
            resources.openRawResource(R.raw.gpm_privileged_apps).bufferedReader().use { it.readText() }
        }.getOrNull()
        CtapHidEndpoint().use { endpoint ->
            val bridge = WebAuthnCtapBridge(endpoint, allowlist)
            val getRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            if (getRequest != null) {
                val responseJson = runCatching { bridge.getAssertion(getRequest) }.getOrElse {
                    Log.e(TAG, "getAssertion failed", it)
                    finishWithError(it.message ?: getString(R.string.provider_get_failed)); return
                }
                Log.i(TAG, "getAssertion ok: $responseJson")
                // Building the framework response can also throw (androidx
                // validates the JSON into a PublicKeyCredential). Catch it here
                // so a malformed response surfaces as a logged, reported error
                // instead of an uncaught crash that dies as a generic
                // "unknown error occurred while talking to the credential manager".
                runCatching {
                    val result = Intent()
                    PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PublicKeyCredential(responseJson)))
                    setResult(RESULT_OK, result); finish()
                }.getOrElse {
                    Log.e(TAG, "getAssertion response conversion failed", it)
                    finishWithError(it.message ?: getString(R.string.provider_get_failed))
                }
                return
            }
            val createRequest = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
            if (createRequest != null) {
                val responseJson = runCatching { bridge.makeCredential(createRequest) }.getOrElse {
                    Log.e(TAG, "makeCredential failed", it)
                    finishWithCreateError(it.message ?: getString(R.string.provider_create_failed)); return
                }
                Log.i(TAG, "makeCredential ok: $responseJson")
                runCatching {
                    val result = Intent()
                    PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(responseJson))
                    setResult(RESULT_OK, result); finish()
                }.getOrElse {
                    Log.e(TAG, "makeCredential response conversion failed", it)
                    finishWithCreateError(it.message ?: getString(R.string.provider_create_failed))
                }
                return
            }
            finishWithError(getString(R.string.provider_request_missing))
        }
    }

    private fun finishWithError(message: String) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(
            result,
            GetCredentialUnknownException(message),
        )
        setResult(RESULT_OK, result)
        finish()
    }

    private fun finishWithCreateError(message: String) {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialException(result, CreateCredentialUnknownException(message))
        setResult(RESULT_OK, result)
        finish()
    }

    private companion object {
        const val TAG = "AbkFidoBridge"
    }
}
