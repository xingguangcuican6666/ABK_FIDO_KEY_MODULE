package com.abk.extension.fido

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialException
import kotlin.concurrent.thread

class CredentialProviderActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        thread(name = "abk-credential-provider") { finishProviderRequest() }
    }

    private fun finishProviderRequest() {
        CtapHidEndpoint().use { endpoint ->
            val bridge = WebAuthnCtapBridge(endpoint)
            val getRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            if (getRequest != null) {
                val responseJson = runCatching { bridge.getAssertion(getRequest) }.getOrElse {
                    finishWithError(it.message ?: "FIDO request failed"); return
                }
                val result = Intent()
                PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PublicKeyCredential(responseJson)), getRequest)
                setResult(RESULT_OK, result); finish(); return
            }
            val createRequest = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
            if (createRequest != null) {
                val responseJson = runCatching { bridge.makeCredential(createRequest) }.getOrElse {
                    finishWithCreateError(it.message ?: "FIDO creation failed"); return
                }
                val result = Intent()
                PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(responseJson))
                setResult(RESULT_OK, result); finish(); return
            }
            finishWithError("Missing Credential Manager request")
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
}
