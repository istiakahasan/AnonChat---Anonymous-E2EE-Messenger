package org.anonchat.network

import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlin.math.min
import kotlin.random.Random

/**
 * Task 5: Tor Transport & Blind Relay API (Android / Kotlin)
 *
 * Connects to Orbot / local Tor daemon via SOCKS5 proxy (127.0.0.1:9050).
 * Handles Tor circuit failures with exponential backoff and jitter.
 */
class TorClient(
    private val serverBaseUrl: String = "http://127.0.0.1:8080",
    private val torHost: String = "127.0.0.1",
    private val torPort: Int = 9050
) {
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    private val okHttpClient: OkHttpClient = OkHttpClient.Builder()
        .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(torHost, torPort)))
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .addInterceptor { chain ->
            // Scrub client identification headers
            val scrubbed = chain.request().newBuilder()
                .removeHeader("User-Agent")
                .header("User-Agent", "AnonChat-Android/1.0")
                .build()
            chain.proceed(scrubbed)
        }
        .build()

    /**
     * Executes an HTTP call with exponential backoff retry on Tor circuit drop.
     */
    fun executeWithRetry(request: Request, maxRetries: Int = 5): Response {
        var attempt = 0
        var lastException: IOException? = null

        while (attempt < maxRetries) {
            attempt++
            try {
                val response = okHttpClient.newCall(request).execute()
                if (response.isSuccessful || response.code == 404) {
                    return response
                }
                response.close()
            } catch (e: IOException) {
                lastException = e
            }

            if (attempt < maxRetries) {
                val delay = min(500L * (1L shl (attempt - 1)), 10000L) + Random.nextLong(0, 500)
                Thread.sleep(delay)
            }
        }

        throw lastException ?: IOException("Tor circuit exhausted after $maxRetries attempts")
    }

    fun uploadPreKeyBundle(bundleJson: JSONObject) {
        val request = Request.Builder()
            .url("$serverBaseUrl/v1/keys")
            .post(bundleJson.toString().toRequestBody(jsonMediaType))
            .build()

        executeWithRetry(request).use { response ->
            if (!response.isSuccessful) {
                throw IOException("Server returned ${response.code} uploading keys: ${response.body?.string()}")
            }
        }
    }

    fun fetchPeerPreKeyBundle(peerUserId: String): JSONObject {
        val request = Request.Builder()
            .url("$serverBaseUrl/v1/keys/$peerUserId")
            .get()
            .build()

        executeWithRetry(request).use { response ->
            if (!response.isSuccessful) {
                throw IOException("Server returned ${response.code} fetching keys: ${response.body?.string()}")
            }
            return JSONObject(response.body?.string() ?: "{}")
        }
    }

    fun enqueueBlob(recipientId: String, base64Blob: String): String {
        val payload = JSONObject().apply {
            put("recipientId", recipientId)
            put("blob", base64Blob)
        }

        val request = Request.Builder()
            .url("$serverBaseUrl/v1/queue")
            .post(payload.toString().toRequestBody(jsonMediaType))
            .build()

        executeWithRetry(request).use { response ->
            if (!response.isSuccessful) {
                throw IOException("Server returned ${response.code} queuing blob")
            }
            val resObj = JSONObject(response.body?.string() ?: "{}")
            return resObj.getString("messageId")
        }
    }

    fun pollQueue(userId: String): JSONObject {
        val request = Request.Builder()
            .url("$serverBaseUrl/v1/queue/$userId")
            .get()
            .build()

        executeWithRetry(request).use { response ->
            if (!response.isSuccessful) {
                throw IOException("Server returned ${response.code} polling queue")
            }
            return JSONObject(response.body?.string() ?: "{}")
        }
    }
}

