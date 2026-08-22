package com.abk.extension.fido

import android.util.Base64
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import java.security.MessageDigest
import org.json.JSONObject

/** Converts the Credential Manager WebAuthn JSON envelope to the kernel CTAP CBOR envelope. */
internal class WebAuthnCtapBridge(private val hid: CtapHidEndpoint) {
    private var cid: Int = -1

    fun getAssertion(request: ProviderGetCredentialRequest): String {
        val option = request.credentialOptions
            .filterIsInstance<GetPublicKeyCredentialOption>()
            .firstOrNull()
            ?: error("missing public key credential option")
        val json = option.requestJson
        val o = JSONObject(json)
        val rpId = o.optString("rpId").ifBlank { error("missing rpId") }
        val clientData = clientData("webauthn.get", o.getString("challenge"), request.callingAppInfo.packageName)
        val allowCredentials: List<ByteArray> = o.optJSONArray("allowCredentials")?.let { array ->
            (0 until array.length()).map { index ->
                val credential = array.getJSONObject(index)
                CborWriter().map(1).int(1).bytes(b64(credential.getString("id"))).build()
            }
        } ?: emptyList()
        val req = CborWriter().map(4)
            .int(1).text(rpId)
            .int(2).bytes(sha256(clientData))
            .int(3).array(allowCredentials)
            .int(5).map(1).text("uv").bool(o.optString("userVerification") == "required")
            .build()
        val response = transact(req)
        val authData = response.bytes(2) ?: error("missing authenticatorData")
        val signature = response.bytes(3) ?: error("missing signature")
        val credentialId = response.mapBytes(1, 1) ?: byteArrayOf()
        val clientDataB64 = enc(clientData)
        return JSONObject().apply {
            put("id", enc(credentialId)); put("rawId", enc(credentialId)); put("type", "public-key")
            put("response", JSONObject().apply {
                put("clientDataJSON", clientDataB64)
                put("authenticatorData", enc(authData)); put("signature", enc(signature))
                put("userHandle", JSONObject.NULL)
            })
        }.toString()
    }

    fun makeCredential(request: ProviderCreateCredentialRequest): String {
        val createRequest = request.callingRequest as? CreatePublicKeyCredentialRequest
            ?: error("missing public key credential request")
        val json = createRequest.requestJson
        val o = JSONObject(json)
        val rp = o.getJSONObject("rp"); val user = o.getJSONObject("user")
        val challenge = o.getString("challenge")
        val clientData = clientData("webauthn.create", challenge, request.callingAppInfo.packageName)
        val params = CborWriter().map(5)
            .int(1).bytes(sha256(clientData)).int(2).map(2)
            .text("id").text(rp.getString("id")).text("name").text(rp.optString("name", rp.getString("id")))
            .int(3).map(3).text("id").bytes(b64(user.getString("id")))
            .text("name").text(user.getString("name")).text("displayName").text(user.optString("displayName", user.getString("name")))
            .int(4).array(listOf(CborWriter().map(2).text("type").text("public-key").text("alg").int(-7).build()))
            .int(7).map(2).text("rk").bool(true).text("uv").bool(false).build()
        val response = transact(params)
        val clientDataB64 = enc(clientData)
        return JSONObject().apply {
            put("id", ""); put("rawId", ""); put("type", "public-key")
            put("response", JSONObject().apply { put("clientDataJSON", clientDataB64); put("attestationObject", enc(response.raw)) })
        }.toString()
    }

    private fun transact(cbor: ByteArray): CborReader {
        if (cid < 0) {
            val nonce = ByteArray(8); java.security.SecureRandom().nextBytes(nonce)
            val init = hid.transceive(0xffffffff.toInt(), 0x06, nonce)
            cid = ((init[8].toInt() and 255) shl 24) or ((init[9].toInt() and 255) shl 16) or
                ((init[10].toInt() and 255) shl 8) or (init[11].toInt() and 255)
        }
        val out = hid.transceive(cid, 0x10, cbor)
        require(out.isNotEmpty() && out[0].toInt() == 0) { "CTAP status=${out.firstOrNull()?.toInt()}" }
        return CborReader(out.copyOfRange(1, out.size))
    }

    private fun clientData(type: String, challenge: String, origin: String?): ByteArray =
        JSONObject().put("type", type).put("challenge", challenge).put("origin", origin ?: "android:abk-fido").toString().toByteArray()

    private fun b64(v: String) = Base64.decode(v, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    private fun enc(v: ByteArray) = Base64.encodeToString(v, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    private fun sha256(v: ByteArray) = MessageDigest.getInstance("SHA-256").digest(v)

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
}

private class CborReader(val raw: ByteArray) {
    private var p = 0
    private fun item(): Pair<Int, Long> { val x = raw[p++].toInt() and 255; val m=x ushr 5; val a=x and 31; val n=when(a){in 0..23->a.toLong();24->raw[p++].toLong() and 255;25->((raw[p++].toLong() and 255) shl 8) or (raw[p++].toLong() and 255);else->error("unsupported CBOR")}; return m to n }
    private fun value(): ByteArray { val (m,n)=item(); val start=p; when(m){0,1->{};2,3->{p+=n.toInt()};4->repeat(n.toInt()){value()};5->repeat(n.toInt()*2){value()};7->{};else->error("unsupported CBOR")}; return raw.copyOfRange(start,p) }
    fun bytes(key: Int): ByteArray? { val save=p; val (m,n)=item(); if(m!=5){p=save;return null}; repeat(n.toInt()){ val k=item(); if(k.first==0 && k.second.toInt()==key){ val (vm,vn)=item(); if(vm==2){val out=raw.copyOfRange(p,p+vn.toInt());p+=vn.toInt(); repeat(n.toInt()*2-2-it*2){value()}; return out}; value() } else value() }; p=save; return null }
    fun mapBytes(key: Int, nestedKey: Int): ByteArray? {
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
