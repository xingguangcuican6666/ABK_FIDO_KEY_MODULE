package com.abk.extension.fido

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.util.Base64
import java.io.File

private const val LOCAL_DB_NAME = "abk_fido.db"
private const val METADATA_DB_PATH = "/metadata/abk_fido.db"
private const val METADATA_BLOB_PATH = "/metadata/abk_fido_store.bin"
private const val STORE_DISK_HEADER_SIZE = 84
private const val STORE_DISK_CRED_SIZE = 484
private const val STORE_DISK_CRED_SIZE_V1 = 452
private const val STORE_DISK_MAX_CREDS = 32
private val syncLock = Any()

private data class PersistenceBackend(
    val name: String,
    val blobPath: String,
    val dbPath: String,
)

private data class PersistedBlob(
    val backend: PersistenceBackend,
    val bytes: ByteArray,
)

private data class PersistedDatabase(
    val backend: PersistenceBackend,
)

private val PERSISTENCE_BACKENDS = listOf(
    PersistenceBackend(
        name = "metadata",
        blobPath = METADATA_BLOB_PATH,
        dbPath = METADATA_DB_PATH,
    ),
)

data class SyncResult(
    val success: Boolean,
    val notes: List<String>,
) {
    fun userMessage(context: Context): String {
        val prefix = if (success) {
            context.getString(R.string.status_success_prefix)
        } else {
            context.getString(R.string.status_failure_prefix)
        }
        return prefix + notes.joinToString("; ").ifBlank { "no-op" }
    }
}

internal class MetadataSyncCoordinator(context: Context) {
    private val appContext = context.applicationContext
    private val deviceContext = appContext.createDeviceProtectedStorageContext()
    internal val localDbFile = deviceContext.getDatabasePath(LOCAL_DB_NAME)
    internal val ownerUid = appContext.applicationInfo.uid

    fun syncNow(reason: String): SyncResult {
        synchronized(syncLock) {
            val notes = mutableListOf("reason=$reason")

            if (!RootShell.isRootAvailable()) {
                notes += appContext.getString(R.string.status_root_missing)
                return SyncResult(success = false, notes = notes)
            }

            val ensureBlobFile = RootShell.ensureEmptyFileIfMissing(METADATA_BLOB_PATH)
            when {
                !ensureBlobFile.success -> {
                    notes += "precreate failed for $METADATA_BLOB_PATH"
                }
                ensureBlobFile.stdout.contains("created") -> {
                    notes += "precreated missing blob file at $METADATA_BLOB_PATH"
                }
            }

            localDbFile.parentFile?.mkdirs()

            var activeBackend = importDatabase()
            if (activeBackend != null) {
                notes += "imported sqlite mirror from ${activeBackend.dbPath}"
                notes += "active_backend=${activeBackend.name}"
            } else {
                notes += "persistent sqlite mirror not found"
            }

            val repository = StoreSnapshotRepository(localDbFile)
            repository.ensureSchema()

            val kernelCredentialCount = FidoKernelBridge.readCredentialCount() ?: 0
            val persistedBlob = readPersistedBlob()
            var localBlob = repository.loadSnapshot()

            when {
                persistedBlob != null -> {
                    activeBackend = persistedBlob.backend
                    notes += "active_backend=${persistedBlob.backend.name}"
                    localBlob = syncSnapshot(
                        repository = repository,
                        currentBlob = localBlob,
                        sourceBlob = persistedBlob.bytes,
                        sourceLabel = persistedBlob.backend.blobPath,
                        notes = notes
                    )
                    val targetCount = persistedBlob.bytes.storeCredentialCount()
                    if (targetCount < 0) {
                        return SyncResult(false, notes + "${persistedBlob.backend.name} blob malformed")
                    }
                    if (shouldRestoreKernel(kernelCredentialCount, targetCount)) {
                        val restoreFailure = restoreKernelFromBlob(
                            restoreBlob = persistedBlob.bytes,
                            preferredBackend = persistedBlob.backend,
                            targetCount = targetCount,
                            notes = notes
                        )
                        if (restoreFailure != null) {
                            return restoreFailure
                        }
                    } else {
                        notes += "kernel already loaded(count=$kernelCredentialCount)"
                    }
                }
                localBlob != null -> {
                    val preferredBackend = activeBackend ?: PERSISTENCE_BACKENDS.last()
                    notes += "active_backend=${preferredBackend.name}"
                    val targetCount = localBlob.storeCredentialCount()
                    if (targetCount < 0) {
                        return SyncResult(false, notes + "local sqlite snapshot malformed")
                    }
                    if (kernelCredentialCount > 0) {
                        return SyncResult(
                            success = false,
                            notes = notes + "persistent blob missing while kernel has credentials"
                        )
                    }
                    notes += "persistent blob missing, restoring from sqlite snapshot"
                    val restoreFailure = restoreKernelFromBlob(
                        restoreBlob = localBlob,
                        preferredBackend = preferredBackend,
                        targetCount = targetCount,
                        notes = notes
                    )
                    if (restoreFailure != null) {
                        return restoreFailure
                    }
                }
                else -> {
                    notes += "no stored blob available"
                }
            }

            val dbBackend = activeBackend ?: PERSISTENCE_BACKENDS.first()
            val exportDbBackend = writeDatabaseToPersistence(dbBackend, notes)
            if (exportDbBackend == null) {
                return SyncResult(false, notes + "failed to export sqlite mirror to persistent storage")
            }
            notes += "exported sqlite mirror to ${exportDbBackend.dbPath}"
            notes += "sqlite_backend=${exportDbBackend.name}"
            return SyncResult(true, notes)
        }
    }
}

private data class KernelRestoreObservation(
    val generation: Int?,
    val credentialCount: Int?,
)

private fun MetadataSyncCoordinator.syncSnapshot(
    repository: StoreSnapshotRepository,
    currentBlob: ByteArray?,
    sourceBlob: ByteArray,
    sourceLabel: String,
    notes: MutableList<String>,
): ByteArray {
    return if (currentBlob == null || !sourceBlob.contentEquals(currentBlob)) {
        repository.saveSnapshot(sourceBlob)
        notes += "updated sqlite snapshot from $sourceLabel blob"
        sourceBlob
    } else {
        notes += "sqlite snapshot already matches $sourceLabel blob"
        currentBlob
    }
}

private fun MetadataSyncCoordinator.shouldRestoreKernel(
    kernelCredentialCount: Int,
    targetCount: Int,
): Boolean {
    return kernelCredentialCount == 0 || (targetCount > 0 && kernelCredentialCount < targetCount)
}

private fun MetadataSyncCoordinator.restoreKernelFromBlob(
    restoreBlob: ByteArray,
    preferredBackend: PersistenceBackend,
    targetCount: Int,
    notes: MutableList<String>,
): SyncResult? {
    val exportBackend = writeBlobToPersistence(
        preferredBackend = preferredBackend,
        restoreBlob = restoreBlob,
        notes = notes
    )
    if (exportBackend == null) {
        return SyncResult(false, notes + "failed to write restore blob to persistent storage")
    }
    notes += "exported restore blob to ${exportBackend.blobPath}"
    notes += "blob_backend=${exportBackend.name}"

    val generationBefore = FidoKernelBridge.readStoreGeneration()
    notes += "generation_before=${generationBefore ?: -1}"

    val restoreTrigger = FidoKernelBridge.restoreMetadata()
    if (!restoreTrigger.success) {
        return kernelRestoreFailure(
            notes = notes,
            reason = "restore trigger failed",
            triggerOutput = restoreTrigger.stdout
        )
    }

    val observation = waitForKernelRestore(targetCount, generationBefore)
    notes += "generation_after=${observation.generation ?: -1}"
    notes += "restored_count=${observation.credentialCount ?: -1}/$targetCount"

    if (generationBefore == null) {
        return kernelRestoreFailure(notes, "generation before restore unavailable")
    }
    if (observation.generation == null || observation.generation <= generationBefore) {
        return kernelRestoreFailure(notes, "restore triggered but generation unchanged")
    }
    if (targetCount > 0 &&
        (observation.credentialCount == null || observation.credentialCount < targetCount)
    ) {
        return kernelRestoreFailure(notes, "restore incomplete")
    }

    notes += "restored persisted blob into kernel"
    return null
}

private fun MetadataSyncCoordinator.importDatabase(): PersistenceBackend? {
    for (backend in PERSISTENCE_BACKENDS) {
        val importDb = RootShell.copyFileFromMetadata(
            backend.dbPath,
            localDbFile.absolutePath,
            ownerUid
        )
        if (importDb.success) {
            return backend
        }
    }
    return null
}

private fun MetadataSyncCoordinator.readPersistedBlob(): PersistedBlob? {
    for (backend in PERSISTENCE_BACKENDS) {
        val blob = RootShell.readFileBase64(backend.blobPath)
            .takeIf { it.success }
            ?.stdout
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?.let { raw -> runCatching { Base64.decode(raw, Base64.DEFAULT) }.getOrNull() }
        if (blob != null) {
            return PersistedBlob(backend = backend, bytes = blob)
        }
    }
    return null
}

private fun MetadataSyncCoordinator.writeBlobToPersistence(
    preferredBackend: PersistenceBackend,
    restoreBlob: ByteArray,
    notes: MutableList<String>,
): PersistenceBackend? {
    val payloadBase64 = Base64.encodeToString(restoreBlob, Base64.NO_WRAP)
    for (backend in orderedBackends(preferredBackend)) {
        val exportBlob = RootShell.writeFileBase64(
            path = backend.blobPath,
            payloadBase64 = payloadBase64
        )
        if (exportBlob.success) {
            return backend
        }
        notes += "write failed for ${backend.blobPath}"
    }
    return null
}

private fun MetadataSyncCoordinator.writeDatabaseToPersistence(
    preferredBackend: PersistenceBackend,
    notes: MutableList<String>,
): PersistenceBackend? {
    for (backend in orderedBackends(preferredBackend)) {
        val exportDb = RootShell.copyFileToMetadata(localDbFile.absolutePath, backend.dbPath)
        if (exportDb.success) {
            return backend
        }
        notes += "sqlite export failed for ${backend.dbPath}"
    }
    return null
}

private fun orderedBackends(preferredBackend: PersistenceBackend): List<PersistenceBackend> {
    return listOf(preferredBackend) + PERSISTENCE_BACKENDS.filter { it != preferredBackend }
}

private fun MetadataSyncCoordinator.waitForKernelRestore(
    targetCount: Int,
    generationBefore: Int?,
    attempts: Int = 20,
    delayMs: Long = 200,
): KernelRestoreObservation {
    repeat(attempts) {
        val generation = FidoKernelBridge.readStoreGeneration()
        val count = FidoKernelBridge.readCredentialCount()
        if (generationBefore != null &&
            generation != null &&
            generation > generationBefore &&
            (targetCount <= 0 || (count != null && count >= targetCount))
        ) {
            return KernelRestoreObservation(generation = generation, credentialCount = count)
        }
        Thread.sleep(delayMs)
    }
    return KernelRestoreObservation(
        generation = FidoKernelBridge.readStoreGeneration(),
        credentialCount = FidoKernelBridge.readCredentialCount()
    )
}

private fun MetadataSyncCoordinator.kernelRestoreFailure(
    notes: List<String>,
    reason: String,
    triggerOutput: String? = null,
): SyncResult {
    val failureNotes = notes.toMutableList()
    failureNotes += reason
    if (!triggerOutput.isNullOrBlank()) {
        failureNotes += "trigger_output=${triggerOutput.toNoteValue()}"
    }
    failureNotes += "kernel_last_error=${FidoKernelBridge.readLastError().toNoteValue()}"
    failureNotes += "kernel_last_trace=${FidoKernelBridge.readLastTrace().toNoteValue()}"
    return SyncResult(success = false, notes = failureNotes)
}

private fun String.toNoteValue(): String {
    val trimmed = trim()
    if (trimmed.isEmpty()) return "none"
    return trimmed.replace(Regex("\\s+"), " ")
}

private fun ByteArray.storeCredentialCount(): Int {
    if (size < STORE_DISK_HEADER_SIZE) return -1
    // Version 1 blobs carry 452-byte slots; v2 slots are 484 bytes with the
    // 32-byte hmac-secret tail.
    val version = (this[4].toInt() and 0xff) or
        ((this[5].toInt() and 0xff) shl 8) or
        ((this[6].toInt() and 0xff) shl 16) or
        ((this[7].toInt() and 0xff) shl 24)
    val credSize = if (version == 1) STORE_DISK_CRED_SIZE_V1 else STORE_DISK_CRED_SIZE
    val credsBytes = size - STORE_DISK_HEADER_SIZE
    if (credsBytes <= 0) return 0
    val slots = minOf(credsBytes / credSize, STORE_DISK_MAX_CREDS)
    var count = 0
    for (i in 0 until slots) {
        val offset = STORE_DISK_HEADER_SIZE + (i * credSize)
        if (getOrNull(offset)?.toInt() == 1) {
            count++
        }
    }
    return count
}

private class StoreSnapshotRepository(private val dbFile: File) {
    fun ensureSchema() {
        val db = openDatabase()
        db.close()
    }

    fun loadSnapshot(): ByteArray? {
        val db = openDatabase()
        return try {
            db.rawQuery("SELECT snapshot_blob FROM store_snapshot WHERE id = 1", null).use { cursor ->
                if (cursor.moveToFirst()) cursor.getBlob(0) else null
            }
        } finally {
            db.close()
        }
    }

    fun saveSnapshot(blob: ByteArray) {
        val db = openDatabase()
        try {
            db.beginTransaction()
            db.execSQL(
                "INSERT OR REPLACE INTO store_snapshot(id, snapshot_blob, updated_at) VALUES(1, ?, ?)",
                arrayOf(blob, System.currentTimeMillis())
            )
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
            db.close()
        }
    }

    private fun openDatabase(): SQLiteDatabase {
        return try {
            openDatabaseInternal()
        } catch (_: Throwable) {
            cleanupDatabaseFiles()
            openDatabaseInternal()
        }
    }

    private fun openDatabaseInternal(): SQLiteDatabase {
        val db = SQLiteDatabase.openOrCreateDatabase(dbFile, null)
        try {
            db.execSQL(
                """
                CREATE TABLE IF NOT EXISTS store_snapshot(
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    snapshot_blob BLOB NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """.trimIndent()
            )
            return db
        } catch (t: Throwable) {
            db.close()
            throw t
        }
    }

    private fun cleanupDatabaseFiles() {
        dbFile.delete()
        File(dbFile.absolutePath + "-journal").delete()
        File(dbFile.absolutePath + "-wal").delete()
        File(dbFile.absolutePath + "-shm").delete()
    }
}
