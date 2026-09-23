package com.abk.extension.fido

import android.util.Base64
import android.util.Log
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject

/** Converts the Credential Manager WebAuthn JSON envelope to the kernel CTAP CBOR envelope. */
internal class WebAuthnCtapBridge(
    private val hid: CtapHidEndpoint,
    /** GPM privileged-browser allowlist JSON, used to recover the web origin. */
    private val privilegedAllowlist: String? = null,
) {
    private var cid: Int = -1

    fun getAssertion(request: ProviderGetCredentialRequest): String {
        val option = request.credentialOptions
            .filterIsInstance<GetPublicKeyCredentialOption>()
            .firstOrNull()
            ?: error("missing public key credential option")
        val json = option.requestJson
        Log.i(TAG, "getAssertion requestJson=$json")
        val o = JSONObject(json)
        val rpId = o.optString("rpId").ifBlank { error("missing rpId") }
        val clientData = clientData("webauthn.get", o.getString("challenge"), resolveOrigin(request.callingAppInfo, rpId))
        // A privileged browser builds and hashes the real clientDataJSON itself,
        // hands us only that hash, and substitutes its own clientDataJSON into
        // the response it returns to the site. Signing the clientData we built
        // locally instead of the supplied hash makes the assertion signature
        // verify against the wrong bytes — the ceremony completes and looks
        // correct here, but the RP rejects it. Prefer the browser's hash; fall
        // back to hashing our own clientData only when none was supplied.
        val clientDataHash = option.clientDataHash ?: sha256(clientData)
        Log.i(TAG, "getAssertion clientDataHash browserSupplied=${option.clientDataHash != null}")
        val allowCredentials: List<ByteArray> = o.optJSONArray("allowCredentials")?.let { array ->
            (0 until array.length()).mapNotNull { index ->
                val credential = array.getJSONObject(index)
                val id = b64(credential.getString("id"))
                // The kernel keys every credential by a 32-byte id, so a longer
                // id cannot be one of ours. A relying party lists every passkey
                // on the account here, including ones from other authenticators,
                // and forwarding an oversized id makes the driver reject the
                // whole request with CTAP2_ERR_INVALID_PARAMETER. Drop it and let
                // the ids that can match — or resident-credential discovery —
                // answer instead.
                if (id.size > MAX_CREDENTIAL_ID) return@mapNotNull null
                // CTAP2 credential descriptors use text keys, unlike the
                // integer-keyed getAssertion request itself.
                CborWriter().map(2)
                    .text("type").text("public-key")
                    .text("id").bytes(id)
                    .build()
            }
        } ?: emptyList()
        val req = CborWriter().map(4)
            .int(1).text(rpId)
            .int(2).bytes(clientDataHash)
            .int(3).array(allowCredentials)
            .int(5).map(1).text("uv").bool(o.optString("userVerification") == "required")
            .build()
        val response = transact(CTAP_GET_ASSERTION, req)
        val authData = response.bytes(2) ?: error("missing authenticatorData")
        val signature = response.bytes(3) ?: error("missing signature")
        val credentialId = response.mapBytes(1, 1) ?: byteArrayOf()
        // The response's user entity (key 4) carries the account handle a
        // discoverable-credential login needs to identify who signed in.
        val userHandle = response.mapBytes(4, 1)
        Log.i(TAG, "getAssertion authData=${authData.size}B sig=${signature.size}B credId=${credentialId.size}B userHandle=${userHandle?.size ?: -1}B")
        val clientDataB64 = enc(clientData)
        return JSONObject().apply {
            put("id", enc(credentialId)); put("rawId", enc(credentialId)); put("type", "public-key")
            put("response", JSONObject().apply {
                put("clientDataJSON", clientDataB64)
                put("authenticatorData", enc(authData)); put("signature", enc(signature))
                if (userHandle != null) put("userHandle", enc(userHandle))
            })
            // Required by AuthenticationResponseJSON; the browser fails to
            // convert the response to its internal object when it is absent.
            put("clientExtensionResults", JSONObject())
        }.toString()
    }

    fun makeCredential(request: ProviderCreateCredentialRequest): String {
        val createRequest = request.callingRequest as? CreatePublicKeyCredentialRequest
            ?: error("missing public key credential request")
        val json = createRequest.requestJson
        Log.i(TAG, "makeCredential requestJson=$json")
        val o = JSONObject(json)
        val rp = o.getJSONObject("rp"); val user = o.getJSONObject("user")
        val challenge = o.getString("challenge")
        val clientData = clientData("webauthn.create", challenge, resolveOrigin(request.callingAppInfo, rp.getString("id")))
        // See getAssertion: a privileged browser supplies the clientDataHash and
        // overrides clientDataJSON in the response, so sign the supplied hash
        // when present and only hash our own clientData as a fallback.
        val clientDataHash = createRequest.clientDataHash ?: sha256(clientData)
        Log.i(TAG, "makeCredential clientDataHash browserSupplied=${createRequest.clientDataHash != null}")
        val params = CborWriter().map(5)
            .int(1).bytes(clientDataHash).int(2).map(2)
            .text("id").text(rp.getString("id")).text("name").text(rp.optString("name", rp.getString("id")))
            .int(3).map(3).text("id").bytes(b64(user.getString("id")))
            .text("name").text(user.getString("name")).text("displayName").text(user.optString("displayName", user.getString("name")))
            .int(4).array(listOf(CborWriter().map(2).text("type").text("public-key").text("alg").int(-7).build()))
            .int(7).map(2).text("rk").bool(true).text("uv").bool(false).build()
        val response = transact(CTAP_MAKE_CREDENTIAL, params)
        val fmtRaw = response.rawValue(1)
        // RegistrationResponseJSON requires id/rawId to be the new credential id.
        // It is not a top-level field of the CTAP response — it lives inside the
        // authenticator data (key 2) attestedCredentialData, so dig it out there.
        val authData = response.bytes(2)
        val attStmtRaw = response.rawValue(3)
        val credentialId = authData?.let { credentialIdFromAuthData(it) } ?: byteArrayOf()
        Log.i(TAG, "makeCredential fmtRaw=${fmtRaw?.size ?: -1}B authData=${authData?.size ?: -1}B attStmt=${attStmtRaw?.size ?: -1}B credId=${credentialId.size}B")
        // The CTAP2 makeCredential response is a CBOR map keyed by integers
        // (1=fmt, 2=authData, 3=attStmt); the WebAuthn attestationObject the
        // browser decodes expects the text keys fmt/authData/attStmt. Re-key it,
        // copying each value verbatim.
        //
        // The keys MUST be emitted in CTAP2 canonical order: sorted by length
        // then bytewise, i.e. fmt(3) < attStmt(7) < authData(8). Chromium's
        // cbor::Reader (Edge is Chromium) enforces canonical ordering by default
        // and rejects an out-of-order map, so the naive integer-order layout
        // fmt/authData/attStmt makes the browser fail the JSON->Mojo conversion
        // with "field missing or invalid: attestationObject" and abort the
        // ceremony client-side, before the RP ever sees it — even though the
        // bytes are valid CBOR that lenient parsers (py_webauthn/cbor2) accept.
        val attestationObject = if (fmtRaw != null && authData != null && attStmtRaw != null) {
            CborWriter().map(3)
                .text("fmt").raw(fmtRaw)
                .text("attStmt").raw(attStmtRaw)
                .text("authData").bytes(authData)
                .build()
        } else {
            response.raw
        }
        val clientDataB64 = enc(clientData)
        return JSONObject().apply {
            put("id", enc(credentialId)); put("rawId", enc(credentialId)); put("type", "public-key")
            put("response", JSONObject().apply {
                put("clientDataJSON", clientDataB64)
                // AuthenticatorAttestationResponseJSON also requires
                // authenticatorData and transports; the browser fails to convert
                // the response without them.
                if (authData != null) put("authenticatorData", enc(authData))
                put("transports", JSONArray().put("internal").put("hybrid"))
                put("attestationObject", enc(attestationObject))
                // publicKeyAlgorithm is a REQUIRED field of
                // AuthenticatorAttestationResponseJSON; Chromium's JSON->Mojo
                // conversion rejects the response with "field missing or
                // invalid: publicKeyAlgorithm" without it. Our CTAP request
                // offers only ES256 (COSE alg -7), so the returned credential is
                // always ES256 — the value is fixed.
                put("publicKeyAlgorithm", -7)
                // publicKey is ALSO required by this Chromium/Edge build: the
                // DER SubjectPublicKeyInfo of the credential public key,
                // base64url. The WebAuthn spec marks getPublicKey() optional
                // ("null if the key is not available"), but Chromium's
                // JSON->Mojo conversion here rejects the response with "field
                // missing or invalid: publicKey" when it is absent — it does
                // NOT derive it from attestationObject. Build the SPKI from the
                // ES256 COSE key embedded in authData's attestedCredentialData.
                val spki = authData?.let { p256SpkiFromAuthData(it) }
                if (spki != null) put("publicKey", enc(spki))
            })
            put("clientExtensionResults", JSONObject())
        }.toString()
    }

    /**
     * A CTAPHID_CBOR message carries the authenticator command as the first
     * byte of its data, followed by the CBOR-encoded parameters. Sending only
     * the parameter map makes the driver read the CBOR map header (0xa?) as the
     * command and reject it with -ENOIOCTLCMD, so the command byte is prepended
     * here.
     */
    private fun transact(command: Int, cbor: ByteArray): CborReader {
        if (cid < 0) {
            val nonce = ByteArray(8); java.security.SecureRandom().nextBytes(nonce)
            val init = hid.transceive(0xffffffff.toInt(), 0x06, nonce)
            cid = ((init[8].toInt() and 255) shl 24) or ((init[9].toInt() and 255) shl 16) or
                ((init[10].toInt() and 255) shl 8) or (init[11].toInt() and 255)
        }
        val message = ByteArray(cbor.size + 1)
        message[0] = command.toByte()
        cbor.copyInto(message, 1)
        Log.i(TAG, "CTAP >> cmd=0x${command.toString(16)} req=${hex(message)}")
        val out = hid.transceive(cid, 0x10, message)
        Log.i(TAG, "CTAP << status=0x${(out.firstOrNull()?.toInt() ?: -1).and(0xff).toString(16)} resp=${hex(out)}")
        require(out.isNotEmpty() && out[0].toInt() == 0) { "CTAP status=${out.firstOrNull()?.toInt()}" }
        return CborReader(out.copyOfRange(1, out.size))
    }

    /**
     * The clientDataJSON origin. A browser calling on behalf of a website
     * supplies the real web origin (e.g. https://github.com), which
     * [CallingAppInfo.getOrigin] returns once the browser is matched against the
     * privileged allowlist. Falls back to the same-origin web origin for an
     * unrecognized browser, and to the package name for a non-browser caller.
     */
    /**
     * Pull the credential id out of authenticator data. Layout: rpIdHash(32) +
     * flags(1) + signCount(4) + attestedCredentialData{ aaguid(16) +
     * credentialIdLength(2, big-endian) + credentialId + COSE key }.
     */
    private fun credentialIdFromAuthData(authData: ByteArray): ByteArray? {
        val lenOffset = 32 + 1 + 4 + 16
        if (authData.size < lenOffset + 2) return null
        val len = ((authData[lenOffset].toInt() and 0xff) shl 8) or (authData[lenOffset + 1].toInt() and 0xff)
        val start = lenOffset + 2
        if (len <= 0 || authData.size < start + len) return null
        return authData.copyOfRange(start, start + len)
    }

    /**
     * Build the DER SubjectPublicKeyInfo (SPKI) that WebAuthn's getPublicKey()
     * returns, from the ES256 COSE key embedded in authenticator data. The COSE
     * key sits right after the credential id in attestedCredentialData:
     * rpIdHash(32)+flags(1)+signCount(4)+aaguid(16)+credIdLen(2)+credId+COSEkey.
     * Our authenticator only ever mints ES256 P-256 keys, whose COSE encoding is
     * the fixed map {1:2, 3:-7, -1:1, -2:x(32), -3:y(32)}; the two 32-byte
     * coordinates are prefixed with the constant P-256 SPKI header to form the
     * 91-byte SubjectPublicKeyInfo.
     */
    private fun p256SpkiFromAuthData(authData: ByteArray): ByteArray? {
        val lenOffset = 32 + 1 + 4 + 16
        if (authData.size < lenOffset + 2) return null
        val credLen = ((authData[lenOffset].toInt() and 0xff) shl 8) or (authData[lenOffset + 1].toInt() and 0xff)
        val coseStart = lenOffset + 2 + credLen
        if (coseStart >= authData.size) return null
        val cose = authData.copyOfRange(coseStart, authData.size)
        // COSE labels -2 (x) and -3 (y) encode as 0x21 / 0x22, each followed by
        // a 32-byte byte string header 0x58 0x20. Find x first, then y after it.
        val x = coseCoord(cose, 0x21, 0) ?: return null
        val y = coseCoord(cose, 0x22, x.second + 32) ?: return null
        return P256_SPKI_PREFIX + cose.copyOfRange(x.second, x.second + 32) +
            cose.copyOfRange(y.second, y.second + 32)
    }

    /**
     * Locate a 32-byte COSE coordinate tagged [label] (0x21 for -2, 0x22 for
     * -3), scanning from [from]. Returns the label and the offset of the
     * coordinate's first byte, or null if the `label 58 20` header is not found.
     */
    private fun coseCoord(cose: ByteArray, label: Int, from: Int): Pair<Int, Int>? {
        var i = from
        while (i + 3 + 32 <= cose.size) {
            if ((cose[i].toInt() and 0xff) == label &&
                (cose[i + 1].toInt() and 0xff) == 0x58 &&
                (cose[i + 2].toInt() and 0xff) == 0x20
            ) {
                return label to (i + 3)
            }
            i++
        }
        return null
    }

    private fun resolveOrigin(caller: CallingAppInfo, rpId: String): String {
        // A WebAuthn origin is scheme://host[:port] with no trailing slash; the
        // browser may hand back "https://github.com/", which the RP rejects.
        val validated = privilegedAllowlist?.let { runCatching { caller.getOrigin(it) }.getOrNull() }
        if (validated != null) return validated.removeSuffix("/")
        val originSupplied = runCatching { caller.isOriginPopulated() }.getOrDefault(false)
        return if (originSupplied) "https://$rpId" else caller.packageName
    }

    private fun clientData(type: String, challenge: String, origin: String?): ByteArray =
        JSONObject().put("type", type).put("challenge", challenge).put("origin", origin ?: "android:abk-fido").toString().toByteArray()

    private fun b64(v: String) = Base64.decode(v, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    private fun enc(v: ByteArray) = Base64.encodeToString(v, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    private fun sha256(v: ByteArray) = MessageDigest.getInstance("SHA-256").digest(v)

    private companion object {
        const val TAG = "AbkFidoBridge"
        const val CTAP_MAKE_CREDENTIAL = 0x01
        const val CTAP_GET_ASSERTION = 0x02
        /** The kernel store keys each credential by a fixed 32-byte id. */
        const val MAX_CREDENTIAL_ID = 32
        /**
         * Constant DER prefix of a P-256 SubjectPublicKeyInfo: SEQUENCE {
         * AlgorithmIdentifier { ecPublicKey, prime256v1 }, BIT STRING { 0x04
         * uncompressed-point marker } }. The 64-byte x||y coordinates follow.
         */
        val P256_SPKI_PREFIX = byteArrayOf(
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(),
            0x48, 0xce.toByte(), 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03,
            0x42, 0x00, 0x04,
        )
        fun hex(v: ByteArray): String = v.joinToString("") { "%02x".format(it) }
    }
}

private class CborWriter(private val b: java.io.ByteArrayOutputStream = java.io.ByteArrayOutputStream()) {
    fun build() = b.toByteArray()
    fun head(major: Int, n: Long): CborWriter { when { n < 24 -> b.write((major shl 5) or n.toInt()); n < 256 -> { b.write((major shl 5) or 24); b.write(n.toInt()) }; n < 65536 -> { b.write((major shl 5) or 25); b.write((n.toInt() ushr 8)); b.write(n.toInt()) }; else -> error("CBOR integer too large") }; return this }
    fun int(n: Int) = if (n >= 0) head(0, n.toLong()) else head(1, (-1L - n)).let { this }
    fun text(s: String): CborWriter { val bytes = s.toByteArray(); head(3, bytes.size.toLong()); b.write(bytes); return this }
    fun bytes(v: ByteArray): CborWriter { head(2, v.size.toLong()); b.write(v); return this }
    fun bool(v: Boolean) = apply { b.write(if (v) 0xf5 else 0xf4) }
    fun map(n: Int) = head(5, n.toLong())
    fun array(values: List<ByteArray>): CborWriter { head(4, values.size.toLong()); values.forEach { b.write(it) }; return this }
    /** Append an already-encoded CBOR item verbatim (used to re-key a map). */
    fun raw(v: ByteArray): CborWriter { b.write(v); return this }
}

private class CborReader(val raw: ByteArray) {
    private var p = 0
    private fun item(): Pair<Int, Long> { val x = raw[p++].toInt() and 255; val m=x ushr 5; val a=x and 31; val n=when(a){in 0..23->a.toLong();24->raw[p++].toLong() and 255;25->((raw[p++].toLong() and 255) shl 8) or (raw[p++].toLong() and 255);else->error("unsupported CBOR")}; return m to n }
    private fun value(): ByteArray { val (m,n)=item(); val start=p; when(m){0,1->{};2,3->{p+=n.toInt()};4->repeat(n.toInt()){value()};5->repeat(n.toInt()*2){value()};7->{};else->error("unsupported CBOR")}; return raw.copyOfRange(start,p) }
    // Each accessor rewinds to the start of the response map and scans it
    // independently. Without the rewind, reading authenticatorData then
    // signature then the credential id in turn walked p off the end of the
    // buffer (ArrayIndexOutOfBounds "length=N; index=N").
    fun bytes(key: Int): ByteArray? {
        p = 0
        val (m, n) = item(); if (m != 5) return null
        repeat(n.toInt()) {
            val k = item()
            if (k.first == 0 && k.second.toInt() == key) {
                val (vm, vn) = item()
                if (vm == 2) { val out = raw.copyOfRange(p, p + vn.toInt()); p += vn.toInt(); return out }
                return null
            }
            value()
        }
        return null
    }
    /** Raw CBOR bytes (head included) of the value at top-level integer [key]. */
    fun rawValue(key: Int): ByteArray? {
        p = 0
        val (m, n) = item(); if (m != 5) return null
        repeat(n.toInt()) {
            val k = item()
            val valueStart = p
            value()
            if (k.first == 0 && k.second.toInt() == key) return raw.copyOfRange(valueStart, p)
        }
        return null
    }

    fun mapBytes(key: Int, nestedKey: Int): ByteArray? {
        p = 0
        val save = p; val (m, n) = item(); if (m != 5) { p = save; return null }
        repeat(n.toInt()) {
            val k = item()
            if (k.first == 0 && k.second.toInt() == key) {
                val (vm, vn) = item(); if (vm != 5) { p = save; return null }
                repeat(vn.toInt()) {
                    val nk = item(); if (nk.first == 3) {
                        val text = raw.copyOfRange(p, p + nk.second.toInt()); p += nk.second.toInt()
                        if (String(text) == "id") { val (bm, bn) = item(); if (bm == 2) { val out = raw.copyOfRange(p, p + bn.toInt()); return out.also { p += bn.toInt() } } }
                        else value()
                    } else value()
                }
            } else value()
        }
        p = save; return null
    }
}
