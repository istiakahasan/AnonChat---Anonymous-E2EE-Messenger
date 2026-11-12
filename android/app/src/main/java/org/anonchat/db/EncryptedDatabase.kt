package org.anonchat.db

import android.content.ContentValues
import android.content.Context
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SQLiteOpenHelper
import java.io.File
import java.util.Timer
import java.util.TimerTask

/**
 * Encrypted Database Layer using SQLCipher for Android (256-bit AES)
 *
 * Security Requirements Checklist Implemented:
 * - [x] No plaintext is ever written to disk without encryption.
 * - [x] Disappearing Messages: Expired rows are purged by a background timer.
 */
class EncryptedDatabase(
    context: Context,
    private val dbPassphrase: ByteArray
) : SQLiteOpenHelper(context, "anonchat_encrypted.db", null, 1) {

    init {
        SQLiteDatabase.loadLibs(context)
        startDisappearingMessagesWorker()
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS contacts (
                friend_code TEXT PRIMARY KEY,
                user_id TEXT NOT NULL UNIQUE,
                nickname TEXT NOT NULL,
                ttl_seconds INTEGER DEFAULT 86400
            );
            """
        )

        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                is_mine INTEGER NOT NULL,
                plaintext TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                expires_at INTEGER
            );
            """
        )

        db.execSQL("CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id);")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_msg_expires ON messages(expires_at);")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {}

    fun getWritableEncryptedDatabase(): SQLiteDatabase {
        return getWritableDatabase(dbPassphrase)
    }

    fun saveMessage(
        id: String,
        conversationId: String,
        senderId: String,
        isMine: Boolean,
        plaintext: String,
        timestamp: Long,
        expiresAt: Long?
    ) {
        val db = getWritableEncryptedDatabase()
        val values = ContentValues().apply {
            put("id", id)
            put("conversation_id", conversationId)
            put("sender_id", senderId)
            put("is_mine", if (isMine) 1 else 0)
            put("plaintext", plaintext)
            put("timestamp", timestamp)
            put("expires_at", expiresAt)
        }
        db.insertWithOnConflict("messages", null, values, SQLiteDatabase.CONFLICT_REPLACE)
    }

    /**
     * Purges expired messages from the local SQLCipher database.
     */
    fun purgeExpiredMessages(): Int {
        val db = getWritableEncryptedDatabase()
        val now = System.currentTimeMillis() / 1000
        return db.delete("messages", "expires_at IS NOT NULL AND expires_at <= ?", arrayOf(now.toString()))
    }

    /**
     * Periodic background worker for Disappearing Messages TTL deletion.
     */
    private fun startDisappearingMessagesWorker() {
        Timer("DisappearingMessagesWorker", true).scheduleAtFixedRate(
            object : TimerTask() {
                override fun run() {
                    try {
                        purgeExpiredMessages()
                    } catch (_: Exception) {}
                }
            },
            10000,
            30000 // runs every 30 seconds
        )
    }
}

