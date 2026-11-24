package br.com.escudodns.adblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Serviço VPN local sem root que intercepta pacotes DNS (porta 53)
 * enviados pelos aplicativos instalados no Android.
 */
class AdBlockVpnService : VpnService() {

    companion object {
        const val ACTION_START = "br.com.escudodns.START"
        const val ACTION_STOP = "br.com.escudodns.STOP"
        private const val CHANNEL_ID = "escudodns_vpn_channel"
        private const val NOTIFICATION_ID = 1001
        private const val LOCAL_TUN_IP = "10.111.222.1"
        private const val VIRTUAL_DNS_IP = "10.111.222.2"
        private const val UPSTREAM_DNS_IP = "94.140.14.14"
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var workerJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, buildNotification())
        startTunnel()
        return START_STICKY
    }

    private fun startTunnel() {
        if (vpnInterface != null) return

        val builder = Builder()
            .setSession("EscudoDNS")
            .addAddress(LOCAL_TUN_IP, 32)
            .addDnsServer(VIRTUAL_DNS_IP)
            .addRoute(VIRTUAL_DNS_IP, 32)
            .setMtu(1500)

        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }

        vpnInterface = builder.establish() ?: return
        val fd = vpnInterface!!.fileDescriptor

        workerJob = serviceScope.launch {
            val input = FileInputStream(fd)
            val output = FileOutputStream(fd)
            val packet = ByteArray(32767)

            while (isActive) {
                val length = input.read(packet)
                if (length <= 0) continue

                val response = DnsPacketInterceptor.handleIpPacket(
                    rawPacket = packet,
                    length = length,
                    forwarder = { dnsPayload -> forwardToUpstream(dnsPayload) }
                )

                if (response != null) {
                    output.write(response)
                }
            }
        }
    }

    private fun forwardToUpstream(dnsPayload: ByteArray): ByteArray? {
        return try {
            DatagramSocket().use { socket ->
                protect(socket)
                socket.soTimeout = 3000
                val upstreamAddr = InetAddress.getByName(UPSTREAM_DNS_IP)
                val outPacket = DatagramPacket(dnsPayload, dnsPayload.size, upstreamAddr, 53)
                socket.send(outPacket)

                val inBuffer = ByteArray(4096)
                val inPacket = DatagramPacket(inBuffer, inBuffer.size)
                socket.receive(inPacket)
                inBuffer.copyOf(inPacket.length)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun stopTunnel() {
        workerJob?.cancel()
        workerJob = null
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
    }

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Proteção EscudoDNS",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }

        val openAppIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("EscudoDNS ativo")
            .setContentText("Bloqueando domínios de publicidade em apps Android")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openAppIntent)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }
}
