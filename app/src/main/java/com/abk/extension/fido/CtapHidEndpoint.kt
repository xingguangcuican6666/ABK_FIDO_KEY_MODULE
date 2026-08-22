package com.abk.extension.fido

import java.io.Closeable
import java.io.IOException
import android.util.Base64

/** Raw 64-byte CTAP HID transport exposed by the kernel for local providers. */
internal class CtapHidEndpoint : Closeable {
    private val ioLock = Any()
    fun transceive(cid: Int, command: Int, payload: ByteArray, timeoutMs: Long = 30_000): ByteArray {
        synchronized(ioLock) { writeMessage(cid, command, payload) }
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        val response = ArrayList<Byte>()
        var expected = -1
        while (System.nanoTime() < deadline) {
            val packet = ByteArray(64)
            val data = synchronized(ioLock) { readPacket() }
            data.copyInto(packet)
            val packetCid = u32(packet, 0)
            if (packetCid != cid) continue
            val head = packet[4].toInt() and 0xff
            if ((head and 0x80) != 0) {
                expected = ((packet[5].toInt() and 0xff) shl 8) or (packet[6].toInt() and 0xff)
                response.clear()
                append(response, packet, 7, minOf(expected, 57))
                if (response.size >= expected) return response.take(expected).toByteArray()
            } else if (expected >= 0) {
                append(response, packet, 5, minOf(expected - response.size, 59))
                if (response.size >= expected) return response.take(expected).toByteArray()
            }
        }
        throw IOException("CTAP HID response timeout")
    }

    fun writePacket(packet: ByteArray) {
        require(packet.size == 64) { "CTAP HID packet must be 64 bytes" }
        val encoded = Base64.encodeToString(packet, Base64.NO_WRAP)
        val result = RootShell.writeDeviceBase64(DEVICE, encoded)
        if (!result.success) throw IOException("write CTAP endpoint failed: ${result.stdout}")
    }

    fun readPacket(): ByteArray {
        val result = RootShell.readDeviceBase64(DEVICE, 64, 40)
        if (!result.success) throw IOException("read CTAP endpoint failed: ${result.stdout}")
        val packet = Base64.decode(result.stdout.trim(), Base64.DEFAULT)
        if (packet.size != 64) throw IOException("short CTAP HID packet: ${packet.size}")
        return packet
    }

    private fun writeMessage(cid: Int, command: Int, payload: ByteArray) {
        var offset = 0
        val first = ByteArray(64)
        putU32(first, 0, cid)
        first[4] = (command or 0x80).toByte()
        first[5] = (payload.size ushr 8).toByte()
        first[6] = payload.size.toByte()
        val firstLen = minOf(payload.size, 57)
        payload.copyInto(first, 7, 0, firstLen)
        writePacket(first)
        offset += firstLen
        var seq = 0
        while (offset < payload.size) {
            val packet = ByteArray(64)
            putU32(packet, 0, cid)
            packet[4] = seq++.toByte()
            val n = minOf(payload.size - offset, 59)
            payload.copyInto(packet, 5, offset, offset + n)
            writePacket(packet)
            offset += n
        }
    }

    private fun append(dst: MutableList<Byte>, src: ByteArray, off: Int, len: Int) {
        for (i in 0 until len) dst.add(src[off + i])
    }

    override fun close() = Unit

    companion object {
        const val DEVICE = "/dev/abk_fido_ctap"
        private fun u32(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 24) or
            ((b[o + 1].toInt() and 0xff) shl 16) or ((b[o + 2].toInt() and 0xff) shl 8) or
            (b[o + 3].toInt() and 0xff)
        private fun putU32(b: ByteArray, o: Int, v: Int) {
            b[o] = (v ushr 24).toByte(); b[o + 1] = (v ushr 16).toByte()
            b[o + 2] = (v ushr 8).toByte(); b[o + 3] = v.toByte()
        }
    }
}
