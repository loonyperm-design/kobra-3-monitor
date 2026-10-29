package com.kobra3.control

import android.util.Base64
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread

class Kobra3LanClient(
    private val onStatusChange: (String, Boolean, Boolean) -> Unit,
    private val onPacketReceived: (String, String) -> Unit
) {
    private val running = AtomicBoolean(false)
    private var activeSocket: SSLSocket? = null
    private var activeOutput: BufferedOutputStream? = null
    private var activeModelId: String = "20024"
    private var activeDeviceId: String = ""

    fun disconnect() {
        running.set(false)
        try {
            activeSocket?.close()
        } catch (_: Exception) {}
        activeSocket = null
        activeOutput = null
    }

    fun sendCommand(type: String, action: String, dataJsonStr: String) {
        thread(name = "Kobra3CmdSender", isDaemon = true) {
            try {
                val out = activeOutput ?: return@thread
                val devId = activeDeviceId.ifEmpty { return@thread }
                val topic = "anycubic/anycubicCloud/v1/web/printer/$activeModelId/$devId/$type"
                val dataObj = if (dataJsonStr.isNotBlank()) JSONObject(dataJsonStr) else JSONObject()
                val payload = JSONObject().apply {
                    put("type", type)
                    put("action", action)
                    put("timestamp", System.currentTimeMillis())
                    put("msgid", UUID.randomUUID().toString())
                    put("data", dataObj)
                }.toString()

                synchronized(out) {
                    out.write(buildMqttPublishPacket(topic, payload))
                    out.flush()
                }
            } catch (_: Exception) {}
        }
    }

    fun connectToPrinter(printerIp: String) {
        disconnect()
        running.set(true)

        thread(name = "Kobra3LanWorker", isDaemon = true) {
            try {
                onStatusChange("Шаг 1/3: Опрос Kobra 3 http://$printerIp:18910/info...", false, false)
                val infoJson = httpGet("http://$printerIp:18910/info")
                val token = infoJson.optString("token", "")
                val modelId = infoJson.optString("modelId", "20024").ifEmpty { "20024" }
                activeModelId = modelId

                if (token.length < 32) {
                    onStatusChange("Ошибка: принтер не вернул 32-байтный токен (Включи LAN Mode!)", false, true)
                    return@thread
                }

                onStatusChange("Шаг 2/3: Рукопожатие /ctrl и расшифровка AES-128-CBC...", false, false)
                val keyPart1 = token.substring(0, 16)
                val aesKeyBytes = token.substring(16, 32).toByteArray(StandardCharsets.UTF_8)

                val ts = System.currentTimeMillis().toString()
                val nonce = UUID.randomUUID().toString().substring(0, 8)
                val did = "kobra3-android-" + UUID.randomUUID().toString().substring(0, 8)

                val innerMd5 = md5Hex(keyPart1)
                val sign = md5Hex(innerMd5 + ts + nonce)

                val ctrlUrl = "http://$printerIp:18910/ctrl?ts=$ts&nonce=$nonce&sign=$sign&did=$did"
                val ctrlJson = httpPost(ctrlUrl)
                val dataObj = ctrlJson.optJSONObject("data")
                    ?: throw IllegalStateException("Пустой блок data в ответе /ctrl")

                val ivStr = dataObj.getString("token")
                val encryptedBase64 = dataObj.getString("info")

                val decryptedStr = decryptAesCbc(
                    cipherTextBase64 = encryptedBase64,
                    keyBytes = aesKeyBytes,
                    ivBytes = ivStr.toByteArray(StandardCharsets.UTF_8)
                )
                val credsJson = JSONObject(decryptedStr)

                val deviceId = credsJson.optString("deviceId", "")
                activeDeviceId = deviceId
                val mqttUser = credsJson.optString("username", "")
                val mqttPass = credsJson.optString("password", "")

                onStatusChange("Шаг 3/3: Подключение к MQTT TLS $printerIp:9883...", false, false)
                runMqttTlsLoop(printerIp, 9883, modelId, deviceId, mqttUser, mqttPass)

            } catch (e: Exception) {
                if (running.get()) {
                    onStatusChange("Ошибка LAN (${printerIp}): ${e.message ?: "Недоступен порт 18910/9883"}", false, true)
                }
            }
        }
    }

    private fun runMqttTlsLoop(
        host: String,
        port: Int,
        modelId: String,
        deviceId: String,
        username: String,
        password: String
    ) {
        val trustAllCerts = arrayOf<X509TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })

        val sslContext = SSLContext.getInstance("TLSv1.2")
        sslContext.init(null, trustAllCerts, SecureRandom())

        val rawSocket = sslContext.socketFactory.createSocket() as SSLSocket
        activeSocket = rawSocket
        rawSocket.connect(InetSocketAddress(host, port), 6000)
        rawSocket.soTimeout = 45000
        rawSocket.startHandshake()

        val input = DataInputStream(BufferedInputStream(rawSocket.inputStream))
        val output = BufferedOutputStream(rawSocket.outputStream)
        activeOutput = output

        val clientId = "kobra3_android_" + UUID.randomUUID().toString().substring(0, 6)
        synchronized(output) {
            output.write(buildMqttConnectPacket(clientId, username, password))
            output.flush()
        }

        val connAckHeader = input.readUnsignedByte()
        val connAckLen = readRemainingLength(input)
        val connAckBody = ByteArray(connAckLen)
        input.readFully(connAckBody)
        if ((connAckHeader shr 4) != 2 || (connAckBody.size >= 2 && connAckBody[1].toInt() != 0)) {
            throw IllegalStateException("Брокер отклонил MQTT CONNECT")
        }

        onStatusChange("Подключен к Kobra 3 ($host:9883) · Управление активно", true, false)

        val wildcardTopic = "anycubic/anycubicCloud/v1/printer/+/$modelId/$deviceId/#"
        synchronized(output) {
            output.write(buildMqttSubscribePacket(1, wildcardTopic))
            val queryTypes = listOf("info", "print", "temp", "multiColorBox", "axis", "video")
            for (qType in queryTypes) {
                val action = when (qType) {
                    "multiColorBox" -> "getInfo"
                    "video" -> "startCapture"
                    else -> "query"
                }
                val qTopic = "anycubic/anycubicCloud/v1/web/printer/$modelId/$deviceId/$qType"
                val qPayload = JSONObject().apply {
                    put("type", qType)
                    put("action", action)
                    put("timestamp", System.currentTimeMillis())
                    put("msgid", UUID.randomUUID().toString())
                    put("data", JSONObject.NULL)
                }.toString()
                output.write(buildMqttPublishPacket(qTopic, qPayload))
            }
            output.flush()
        }

        var lastPingTime = System.currentTimeMillis()

        while (running.get() && !rawSocket.isClosed) {
            val header = input.readUnsignedByte()
            val packetType = header shr 4
            val remLen = readRemainingLength(input)
            val payloadBytes = ByteArray(remLen)
            input.readFully(payloadBytes)

            if (packetType == 3 && remLen > 2) {
                val topicLen = ((payloadBytes[0].toInt() and 0xFF) shl 8) or (payloadBytes[1].toInt() and 0xFF)
                val qos = (header shr 1) and 0x03
                val headerOffset = 2 + topicLen + if (qos > 0) 2 else 0
                if (headerOffset <= payloadBytes.size) {
                    val topicStr = String(payloadBytes, 2, topicLen, StandardCharsets.UTF_8)
                    val msgStr = String(payloadBytes, headerOffset, payloadBytes.size - headerOffset, StandardCharsets.UTF_8)
                    onPacketReceived(topicStr, msgStr)
                }
            }

            val now = System.currentTimeMillis()
            if (now - lastPingTime > 20_000) {
                synchronized(output) {
                    output.write(byteArrayOf(0xC0.toByte(), 0x00))
                    output.flush()
                }
                lastPingTime = now
            }
        }
    }

    private fun httpGet(urlStr: String): JSONObject {
        val conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 5000
            readTimeout = 5000
        }
        return JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
    }

    private fun httpPost(urlStr: String): JSONObject {
        val conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 5000
            readTimeout = 5000
        }
        conn.outputStream.use { it.write(ByteArray(0)) }
        return JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
    }

    private fun md5Hex(input: String): String {
        val digest = MessageDigest.getInstance("MD5").digest(input.toByteArray(StandardCharsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun decryptAesCbc(cipherTextBase64: String, keyBytes: ByteArray, ivBytes: ByteArray): String {
        val cipherBytes = Base64.decode(cipherTextBase64, Base64.DEFAULT)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), IvParameterSpec(ivBytes))
        return String(cipher.doFinal(cipherBytes), StandardCharsets.UTF_8)
    }

    private fun buildMqttConnectPacket(clientId: String, username: String, password: String): ByteArray {
        val body = ByteArrayOutputStream()
        writeMqttString(body, "MQTT")
        body.write(4)
        body.write(0xC2)
        body.write(0)
        body.write(60)
        writeMqttString(body, clientId)
        writeMqttString(body, username)
        writeMqttString(body, password)
        return wrapFixedHeader(0x10, body.toByteArray())
    }

    private fun buildMqttSubscribePacket(packetId: Int, topic: String): ByteArray {
        val body = ByteArrayOutputStream()
        body.write((packetId shr 8) and 0xFF)
        body.write(packetId and 0xFF)
        writeMqttString(body, topic)
        body.write(0)
        return wrapFixedHeader(0x82, body.toByteArray())
    }

    private fun buildMqttPublishPacket(topic: String, jsonPayload: String): ByteArray {
        val body = ByteArrayOutputStream()
        writeMqttString(body, topic)
        body.write(jsonPayload.toByteArray(StandardCharsets.UTF_8))
        return wrapFixedHeader(0x30, body.toByteArray())
    }

    private fun writeMqttString(out: ByteArrayOutputStream, value: String) {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        out.write((bytes.size shr 8) and 0xFF)
        out.write(bytes.size and 0xFF)
        out.write(bytes)
    }

    private fun wrapFixedHeader(firstByte: Int, variableAndPayload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(firstByte)
        var x = variableAndPayload.size
        do {
            var encodedByte = x % 128
            x /= 128
            if (x > 0) encodedByte = encodedByte or 128
            out.write(encodedByte)
        } while (x > 0)
        out.write(variableAndPayload)
        return out.toByteArray()
    }

    private fun readRemainingLength(input: DataInputStream): Int {
        var multiplier = 1
        var value = 0
        while (true) {
            val encodedByte = input.readUnsignedByte()
            value += (encodedByte and 127) * multiplier
            if ((encodedByte and 128) == 0) break
            multiplier *= 128
        }
        return value
    }
}
