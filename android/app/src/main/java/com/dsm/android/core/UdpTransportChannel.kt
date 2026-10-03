package com.dsm.android.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress

/**
 * UDP [TransportChannel] over a connected, VpnService-protected [DatagramSocket].
 *
 * [socketFactory] MUST return a freshly `protect()`-ed (so its packets egress
 * the real network instead of looping back through the TUN) and connected
 * socket. It is invoked once at construction and again on each
 * [rebindToFreshPort] so a rekey can move the client to a new ephemeral source
 * port (H-ANON-4) without leaking traffic outside the tunnel.
 */
class UdpTransportChannel(
    private val server: InetSocketAddress,
    private val socketFactory: () -> DatagramSocket,
) : TransportChannel {

    @Volatile
    private var socket: DatagramSocket = socketFactory()

    override fun send(frame: ByteArray) {
        socket.send(DatagramPacket(frame, frame.size, server))
    }

    override fun recv(): ByteArray {
        // One frame per datagram. Size the buffer above the max wire frame.
        val buf = ByteArray(RECV_BUF_SIZE)
        val pkt = DatagramPacket(buf, buf.size)
        socket.receive(pkt)
        return buf.copyOf(pkt.length)
    }

    override fun rebindToFreshPort() {
        val fresh = socketFactory()
        val old = socket
        socket = fresh
        runCatching { old.close() }
    }

    override fun close() {
        runCatching { socket.close() }
    }

    private companion object {
        const val RECV_BUF_SIZE = 2048
    }
}
