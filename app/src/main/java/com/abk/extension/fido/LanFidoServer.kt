package com.abk.extension.fido

import android.util.Log
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.net.Socket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Encrypted LAN CTAP HID relay. Pairing code is the user-visible PSK. */
internal class LanFidoServer(private val pairingCode: String, private val port: Int = 38741) {
    @Volatile private var running = false
    private var server: ServerSocket? = null
    private var discovery: DatagramSocket? = null

    fun start() {
        if (running) return
        running = true
        startDiscovery()
        Thread {
            runCatching {
                server = ServerSocket(port)
                while (running) server?.accept()?.let { socket -> Thread { serve(socket) }.start() }
            }.onFailure { Log.e(TAG, "LAN FIDO server stopped", it) }
        }.start()
    }

    fun stop() { running = false; server?.close(); discovery?.close(); server = null; discovery = null }

    private fun serve(socket: Socket) {
        socket.use {
            val input = DataInputStream(it.getInputStream()); val output = DataOutputStream(it.getOutputStream())
            val clientNonce = ByteArray(16); input.readFully(clientNonce)
            val serverNonce = ByteArray(16); SecureRandom().nextBytes(serverNonce); output.write(serverNonce); output.flush()
            val key = derive(pairingCode, clientNonce + serverNonce)
            CtapHidEndpoint().use { endpoint ->
                val reader = Thread {
                    runCatching { while (running && !it.isClosed) writeFrame(output, key, endpoint.readPacket()) }
                }.also { thread -> thread.start() }
                while (running) {
                    val request = readFrame(input, key) ?: break
                    if (request.size != 64) break
                    endpoint.writePacket(request)
                }
                reader.interrupt()
            }
        }
    }

    private fun startDiscovery() {
        Thread {
            runCatching {
                discovery = DatagramSocket(DISCOVERY_PORT).apply { broadcast = true }
                val buf = ByteArray(64)
                while (running) {
                    val packet = DatagramPacket(buf, buf.size); discovery?.receive(packet)
                    if (String(packet.data, 0, packet.length) == DISCOVER) {
                        val reply = HERE.toByteArray()
                        discovery?.send(DatagramPacket(reply, reply.size, packet.address, packet.port))
                    }
                }
            }.onFailure { if (running) Log.w(TAG, "LAN discovery stopped", it) }
        }.start()
    }

    private fun derive(password: String, salt: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256"); mac.init(SecretKeySpec(password.toByteArray(), "HmacSHA256"))
        var t = mac.doFinal(salt + byteArrayOf(0, 0, 0, 1)); val out = t.copyOf()
        repeat(99_999) { t = mac.doFinal(t); for (i in out.indices) out[i] = (out[i].toInt() xor t[i].toInt()).toByte() }
        return out
    }

    private fun readFrame(input: DataInputStream, key: ByteArray): ByteArray? {
        val len = input.readInt(); if (len !in 1..4096) return null
        val nonce = ByteArray(12); input.readFully(nonce); val body = ByteArray(len); input.readFully(body)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)); return cipher.doFinal(body)
    }

    private fun writeFrame(output: DataOutputStream, key: ByteArray, payload: ByteArray) {
        val nonce = ByteArray(12); SecureRandom().nextBytes(nonce); val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)); val body = cipher.doFinal(payload)
        output.writeInt(body.size); output.write(nonce); output.write(body); output.flush()
    }

    companion object {
        private const val TAG = "AbkLanFido"
        private const val DISCOVERY_PORT = 38740
        private const val DISCOVER = "ABK_FIDO_DISCOVER_V1"
        private const val HERE = "ABK_FIDO_HERE_V1"
    }
}
