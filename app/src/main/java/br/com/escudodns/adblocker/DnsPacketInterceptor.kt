package br.com.escudodns.adblocker

import java.nio.ByteBuffer

object BlocklistCatalog {
    val allowedDomains: Set<String> = setOf(
        "pix.bcb.gov.br"
    )

    val blockedDomains: Set<String> = setOf(
        "ad.kwai.com",
        "ads-api.twitter.com",
        "ads-sg.tiktok.com",
        "ads.api.vungle.com",
        "ads.chartboost.com",
        "ads.inmobi.com",
        "ads.mopub.com",
        "ads.pangle.io",
        "ads.pinterest.com",
        "ads.pubmatic.com",
        "ads.snapchat.com",
        "ads.tiktok.com",
        "adservice.google.com",
        "an.facebook.com",
        "analytics.tiktok.com",
        "api.ad.xiaomi.com",
        "api.amplitude.com",
        "api.mixpanel.com",
        "api.vungle.com",
        "api16-access-ttp.tiktokpangle.us",
        "api2.amplitude.com",
        "api2.branch.io",
        "app-measurement.com",
        "app.adjust.com",
        "app.appsflyer.com",
        "as-sec.casalemedia.com",
        "bidder.criteo.com",
        "bnc.lt",
        "cdn.liftoff.io",
        "cdn.mxpnl.com",
        "cdn.taboola.com",
        "config.uca.cloud.unity3d.com",
        "d.applovin.com",
        "data.mistat.intl.xiaomi.com",
        "data.mistat.xiaomi.com",
        "dqa.samsung.com",
        "events.split.io",
        "fastlane.rubiconproject.com",
        "firebaselogging-pa.googleapis.com",
        "googleads.g.doubleclick.net",
        "gpm.samsungqbe.com",
        "hbopenbid.pubmatic.com",
        "init.supersonicads.com",
        "launches.appsflyer.com",
        "log-va.tiktokv.com",
        "log.outbrain.com",
        "logservice.hicloud.com",
        "mediation.adnxs.com",
        "metrics.data.hicloud.com",
        "metrics.samsung.com",
        "ms.applovin.com",
        "outcome-ssp.supersonicads.com",
        "pagead2.googlesyndication.com",
        "pixel.facebook.com",
        "rt.applovin.com",
        "rtb.openx.net",
        "s2s.adjust.com",
        "samsungads.com",
        "sdk.iad-01.braze.com",
        "sdkconfig.ad.intl.xiaomi.com",
        "sdkconfig.ad.xiaomi.com",
        "securepubads.g.doubleclick.net",
        "static.criteo.net",
        "t.appsflyer.com",
        "tpc.googlesyndication.com",
        "tr.snapchat.com",
        "tracking.miui.com",
        "trc.taboola.com",
        "trk.pinterest.com",
        "unityads.unity3d.com",
        "widgets.outbrain.com"
    )

    fun isBlocked(domain: String): Boolean {
        val clean = domain.lowercase().trimEnd('.')
        if (allowedDomains.contains(clean)) return false
        var candidate = clean
        while (candidate.contains('.')) {
            if (blockedDomains.contains(candidate)) return true
            candidate = candidate.substringAfter('.')
        }
        return false
    }
}

object DnsPacketInterceptor {

    fun handleIpPacket(
        rawPacket: ByteArray,
        length: Int,
        forwarder: (ByteArray) -> ByteArray?
    ): ByteArray? {
        if (length < 28) return null
        val version = (rawPacket[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ipHeaderLen = (rawPacket[0].toInt() and 0x0F) * 4
        val protocol = rawPacket[9].toInt() and 0xFF
        if (protocol != 17 || length < ipHeaderLen + 8) return null

        val destPort = ((rawPacket[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
            (rawPacket[ipHeaderLen + 3].toInt() and 0xFF)
        if (destPort != 53) return null

        val dnsOffset = ipHeaderLen + 8
        val dnsPayload = rawPacket.copyOfRange(dnsOffset, length)
        val queriedDomain = extractQueryDomain(dnsPayload)

        val dnsResponse = if (queriedDomain != null && BlocklistCatalog.isBlocked(queriedDomain)) {
            buildNxDomainResponse(dnsPayload)
        } else {
            forwarder(dnsPayload)
        } ?: return null

        return wrapUdpResponse(rawPacket, ipHeaderLen, dnsResponse)
    }

    private fun extractQueryDomain(dns: ByteArray): String? {
        if (dns.size < 13) return null
        val labels = mutableListOf<String>()
        var idx = 12
        while (idx < dns.size) {
            val len = dns[idx].toInt() and 0xFF
            if (len == 0) break
            idx++
            if (idx + len > dns.size) return null
            labels.add(String(dns, idx, len, Charsets.US_ASCII))
            idx += len
        }
        return if (labels.isEmpty()) null else labels.joinToString(".")
    }

    private fun buildNxDomainResponse(query: ByteArray): ByteArray {
        val resp = query.copyOf()
        resp[2] = ((resp[2].toInt() or 0x80) and 0xFF).toByte()
        resp[3] = ((resp[3].toInt() and 0xF0) or 0x03).toByte()
        return resp
    }

    private fun wrapUdpResponse(
        origIpPacket: ByteArray,
        ipHeaderLen: Int,
        dnsResponse: ByteArray
    ): ByteArray {
        val udpLen = 8 + dnsResponse.size
        val totalLen = ipHeaderLen + udpLen
        val out = ByteArray(totalLen)

        System.arraycopy(origIpPacket, 0, out, 0, ipHeaderLen)
        System.arraycopy(origIpPacket, 16, out, 12, 4)
        System.arraycopy(origIpPacket, 12, out, 16, 4)

        val buf = ByteBuffer.wrap(out)
        buf.putShort(2, totalLen.toShort())
        buf.putShort(10, 0)
        buf.putShort(10, ipv4Checksum(out, ipHeaderLen))

        out[ipHeaderLen] = origIpPacket[ipHeaderLen + 2]
        out[ipHeaderLen + 1] = origIpPacket[ipHeaderLen + 3]
        out[ipHeaderLen + 2] = origIpPacket[ipHeaderLen]
        out[ipHeaderLen + 3] = origIpPacket[ipHeaderLen + 1]

        buf.putShort(ipHeaderLen + 4, udpLen.toShort())
        buf.putShort(ipHeaderLen + 6, 0)
        System.arraycopy(dnsResponse, 0, out, ipHeaderLen + 8, dnsResponse.size)

        return out
    }

    private fun ipv4Checksum(header: ByteArray, len: Int): Short {
        var sum = 0
        var i = 0
        while (i < len) {
            val word = ((header[i].toInt() and 0xFF) shl 8) or (header[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toShort()
    }
}
