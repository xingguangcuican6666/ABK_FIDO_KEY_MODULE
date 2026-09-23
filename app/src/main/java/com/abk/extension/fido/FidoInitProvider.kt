package com.abk.extension.fido

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.util.Log

class FidoInitProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        Log.i(TAG, "provider init")
        context?.let {
            FidoKeepAliveJobService.schedule(it)
            // onCreate runs on every cold start of this process, including when
            // the system spawns it in the background to serve a Credential
            // Manager ceremony. requestSync tolerates the background
            // foreground-service-start restriction — an unguarded start here
            // throws ForegroundServiceStartNotAllowedException, which crashes
            // this ContentProvider.onCreate and takes the ceremony down as a
            // generic "unknown error". The foreground provider activity starts
            // the service from a context where the start is allowed.
            FidoSyncService.requestSync(it, "provider_init")
        }
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?
    ): Int = 0

    companion object {
        private const val TAG = "AbkFidoCompanion"
    }
}
