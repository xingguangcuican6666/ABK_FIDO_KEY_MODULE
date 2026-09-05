package com.abk.extension.fido

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * The `.abkfido` key file used by export and import.
 *
 * A credential slot carries its private key, so the archive is always
 * encrypted: PBKDF2-HMAC-SHA256 stretches the user's passphrase and AES-256-GCM
 * seals a small JSON document, with the plaintext header as associated data so
 * the iteration count and salt cannot be tampered with.
 *
 *     "ABKFIDO1" | version:1 | iterations:4 BE | salt:16 | nonce:12 | sealed
 */
internal object KeyArchive {
    private val MAGIC = "ABKFIDO1".toByteArray(Charsets.US_ASCII)
    private const val VERSION = 1
    private const val ITERATIONS = 210_000
    private const val SALT_LEN = 16
    private const val NONCE_LEN = 12
    private const val KEY_BITS = 256
    private const val HEADER_LEN = 8 + 1 + 4 + SALT_LEN + NONCE_LEN

    const val FILE_EXTENSION = "abkfido"
    const val MIME_TYPE = "application/octet-stream"

    class ArchiveError(message: String) : Exception(message)

    fun export(records: List<FidoCredentialRecord>, passphrase: CharArray): ByteArray {
        val document = JSONObject()
            .put("v", VERSION)
            .put("exported_at", System.currentTimeMillis())
            .put("keys", JSONArray().apply { records.forEach { put(it.toJson()) } })
        val plaintext = document.toString().toByteArray(Charsets.UTF_8)

        val random = SecureRandom()
        val salt = ByteArray(SALT_LEN).also(random::nextBytes)
        val nonce = ByteArray(NONCE_LEN).also(random::nextBytes)
        val header = ByteArray(HEADER_LEN)
        MAGIC.copyInto(header, 0)
        header[8] = VERSION.toByte()
        header[9] = ((ITERATIONS ushr 24) and 0xff).toByte()
        header[10] = ((ITERATIONS ushr 16) and 0xff).toByte()
        header[11] = ((ITERATIONS ushr 8) and 0xff).toByte()
        header[12] = (ITERATIONS and 0xff).toByte()
        salt.copyInto(header, 13)
        nonce.copyInto(header, 13 + SALT_LEN)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            deriveKey(passphrase, salt, ITERATIONS),
            GCMParameterSpec(128, nonce),
        )
        cipher.updateAAD(header)
        val sealed = cipher.doFinal(plaintext)
        return header + sealed
    }

    /** @throws ArchiveError when the file is not an archive or the passphrase is wrong. */
    fun import(bytes: ByteArray, passphrase: CharArray): List<FidoCredentialRecord> {
        if (bytes.size <= HEADER_LEN) throw ArchiveError("this file is not an ABK FIDO key file")
        if (!bytes.copyOfRange(0, 8).contentEquals(MAGIC)) {
            throw ArchiveError("this file is not an ABK FIDO key file")
        }
        val version = bytes[8].toInt() and 0xff
        if (version != VERSION) throw ArchiveError("unsupported key file version $version")
        val iterations = ((bytes[9].toInt() and 0xff) shl 24) or
            ((bytes[10].toInt() and 0xff) shl 16) or
            ((bytes[11].toInt() and 0xff) shl 8) or
            (bytes[12].toInt() and 0xff)
        if (iterations !in 1_000..2_000_000) throw ArchiveError("key file header is corrupt")
        val salt = bytes.copyOfRange(13, 13 + SALT_LEN)
        val nonce = bytes.copyOfRange(13 + SALT_LEN, HEADER_LEN)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            deriveKey(passphrase, salt, iterations),
            GCMParameterSpec(128, nonce),
        )
        cipher.updateAAD(bytes, 0, HEADER_LEN)
        val plaintext = try {
            cipher.doFinal(bytes, HEADER_LEN, bytes.size - HEADER_LEN)
        } catch (_: AEADBadTagException) {
            throw ArchiveError("wrong passphrase, or the key file was modified")
        }

        val document = runCatching { JSONObject(String(plaintext, Charsets.UTF_8)) }.getOrNull()
            ?: throw ArchiveError("key file contents are corrupt")
        val keys = document.optJSONArray("keys") ?: throw ArchiveError("key file has no keys")
        val records = ArrayList<FidoCredentialRecord>(keys.length())
        for (i in 0 until keys.length()) {
            val entry = keys.optJSONObject(i) ?: continue
            records += entry.toRecord()
        }
        if (records.isEmpty()) throw ArchiveError("key file has no keys")
        return records
    }

    private fun deriveKey(passphrase: CharArray, salt: ByteArray, iterations: Int): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256")
        val spec = PBEKeySpec(passphrase, salt, iterations, KEY_BITS)
        return try {
            SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
        } finally {
            spec.clearPassword()
        }
    }

    private fun FidoCredentialRecord.toJson(): JSONObject = JSONObject()
        .put("rp", rpId)
        .put("name", userName)
        .put("display", userDisplay)
        .put("resident", resident)
        .put("user_id_len", userIdLen)
        .put("cred_id", credId.b64())
        .put("user_id", userId.b64())
        .put("priv_key", privKey.b64())
        .put("pub_key", pubKey.b64())
        .put("hmac_secret", hmacSecret.b64())

    private fun JSONObject.toRecord(): FidoCredentialRecord {
        val credId = optString("cred_id").b64()
        val privKey = optString("priv_key").b64()
        val hmacSecret = optString("hmac_secret").b64().let {
            if (it.size == 32) it else ByteArray(32)
        }
        if (credId.size != 32 || privKey.size != 32) {
            throw ArchiveError("key file holds a malformed credential")
        }
        return FidoCredentialRecord(
            slot = -1,
            resident = optBoolean("resident", true),
            userIdLen = optInt("user_id_len", 0),
            credId = credId,
            userId = optString("user_id").b64(),
            rpId = optString("rp"),
            userName = optString("name"),
            userDisplay = optString("display"),
            privKey = privKey,
            pubKey = optString("pub_key").b64(),
            hmacSecret = hmacSecret,
        )
    }

    private fun ByteArray.b64(): String = Base64.encodeToString(this, Base64.NO_WRAP)

    private fun String.b64(): ByteArray =
        runCatching { Base64.decode(this, Base64.DEFAULT) }.getOrElse { ByteArray(0) }
}
