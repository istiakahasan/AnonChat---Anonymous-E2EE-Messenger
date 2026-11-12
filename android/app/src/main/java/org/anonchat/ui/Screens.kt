package org.anonchat.ui

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

/**
 * Task 6: UI Skeleton (Android Jetpack Compose)
 *
 * Implements:
 * - Onboarding: Friend Code (Fingerprint) + QR Code.
 * - Chat List: Shows local contacts.
 * - Chat View: Input field, send button, and message list.
 * - Disappearing Messages: TTL dropdown/toggle (Off, 1h, 24h, 7d).
 */

enum class Screen { ONBOARDING, CHAT_LIST, CHAT_VIEW }

data class ContactItem(val friendCode: String, val userId: String, val nickname: String, var ttlSeconds: Long?)
data class MessageItem(val id: String, val senderId: String, val isMine: Boolean, val text: String, val timestamp: Long)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AnonChatAppScreen(myFriendCode: String) {
    var currentScreen by remember { mutableStateOf(Screen.ONBOARDING) }
    var selectedContact by remember { mutableStateOf<ContactItem?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("🔒 AnonChat", fontWeight = FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ),
                actions = {
                    TextButton(onClick = { currentScreen = Screen.ONBOARDING }) {
                        Text("🔑 Identity")
                    }
                    TextButton(onClick = { currentScreen = Screen.CHAT_LIST }) {
                        Text("💬 Chats")
                    }
                }
            )
        }
    ) { padding ->
        Box(modifier = Modifier.padding(padding)) {
            when (currentScreen) {
                Screen.ONBOARDING -> OnboardingScreen(myFriendCode) {
                    currentScreen = Screen.CHAT_LIST
                }
                Screen.CHAT_LIST -> ChatListScreen(
                    onSelectContact = { contact ->
                        selectedContact = contact
                        currentScreen = Screen.CHAT_VIEW
                    }
                )
                Screen.CHAT_VIEW -> {
                    selectedContact?.let { contact ->
                        ChatViewScreen(contact = contact, onBack = { currentScreen = Screen.CHAT_LIST })
                    } ?: run {
                        currentScreen = Screen.CHAT_LIST
                    }
                }
            }
        }
    }
}

@Composable
fun OnboardingScreen(friendCode: String, onProceed: () -> Unit) {
    val qrBitmap = remember(friendCode) { generateQrBitmap(friendCode, 512) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("Your Cryptographic Identity", fontSize = 22.sp, fontWeight = FontWeight.Bold)
        Text(
            "No phone. No email. 100% Anonymous via Tor.",
            color = MaterialTheme.colorScheme.secondary,
            modifier = Modifier.padding(bottom = 20.dp)
        )

        qrBitmap?.let {
            Image(
                bitmap = it.asImageBitmap(),
                contentDescription = "Friend Code QR",
                modifier = Modifier.size(220.dp)
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
        Text("Friend Code:", fontWeight = FontWeight.SemiBold)
        Text(
            friendCode,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
            modifier = Modifier
                .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(6.dp))
                .padding(8.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))
        Button(onClick = onProceed) {
            Text("Open Encrypted Messenger →")
        }
    }
}

@Composable
fun ChatListScreen(onSelectContact: (ContactItem) -> Unit) {
    val contacts = remember {
        mutableStateListOf(
            ContactItem("anon:fc:9a8b7c...", "9a8b7c...", "Alice", 86400L),
            ContactItem("anon:fc:1d2e3f...", "1d2e3f...", "Bob", 3600L)
        )
    }

    LazyColumn(modifier = Modifier.fillMaxSize()) {
        items(contacts) { contact ->
            ListItem(
                headlineContent = { Text(contact.nickname, fontWeight = FontWeight.Bold) },
                supportingContent = { Text(contact.friendCode, maxLines = 1) },
                trailingContent = {
                    val ttlLabel = when (contact.ttlSeconds) {
                        3600L -> "⏳ 1h"
                        86400L -> "⏳ 24h"
                        else -> "⏳ Off"
                    }
                    Badge { Text(ttlLabel) }
                },
                modifier = Modifier.clickable { onSelectContact(contact) }
            )
            Divider()
        }
    }
}

@Composable
fun ChatViewScreen(contact: ContactItem, onBack: () -> Unit) {
    var messageText by remember { mutableStateOf("") }
    var selectedTtl by remember { mutableStateOf(contact.ttlSeconds ?: 86400L) }
    var expandedDropdown by remember { mutableStateOf(false) }

    val messages = remember {
        mutableStateListOf(
            MessageItem("1", contact.userId, false, "Hello! Connected via X3DH & Tor.", System.currentTimeMillis() - 60000),
            MessageItem("2", "me", true, "Verified. Messages are padded to 4KB.", System.currentTimeMillis() - 30000)
        )
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // Chat Header with TTL dropdown
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceVariant)
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(contact.nickname, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                Text(contact.friendCode, fontSize = 11.sp, color = MaterialTheme.colorScheme.secondary)
            }

            Box {
                Button(onClick = { expandedDropdown = true }) {
                    val label = when (selectedTtl) {
                        3600L -> "TTL: 1h"
                        86400L -> "TTL: 24h"
                        604800L -> "TTL: 7d"
                        else -> "TTL: Off"
                    }
                    Text(label)
                }
                DropdownMenu(expanded = expandedDropdown, onDismissRequest = { expandedDropdown = false }) {
                    DropdownMenuItem(text = { Text("TTL: Off") }, onClick = { selectedTtl = 0L; expandedDropdown = false })
                    DropdownMenuItem(text = { Text("TTL: 1 Hour") }, onClick = { selectedTtl = 3600L; expandedDropdown = false })
                    DropdownMenuItem(text = { Text("TTL: 24 Hours") }, onClick = { selectedTtl = 86400L; expandedDropdown = false })
                    DropdownMenuItem(text = { Text("TTL: 7 Days") }, onClick = { selectedTtl = 604800L; expandedDropdown = false })
                }
            }
        }

        // Timeline
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(8.dp),
            reverseLayout = false
        ) {
            items(messages) { msg ->
                val alignment = if (msg.isMine) Alignment.End else Alignment.Start
                val bgColor = if (msg.isMine) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondaryContainer
                val textColor = if (msg.isMine) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSecondaryContainer

                Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = alignment) {
                    Box(
                        modifier = Modifier
                            .background(bgColor, RoundedCornerShape(12.dp))
                            .padding(12.dp)
                    ) {
                        Text(msg.text, color = textColor)
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                }
            }
        }

        // Input bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            TextField(
                value = messageText,
                onValueChange = { messageText = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Encrypted message...") }
            )
            Spacer(modifier = Modifier.width(8.dp))
            Button(
                onClick = {
                    if (messageText.isNotBlank()) {
                        messages.add(
                            MessageItem(
                                id = java.util.UUID.randomUUID().toString(),
                                senderId = "me",
                                isMine = true,
                                text = messageText,
                                timestamp = System.currentTimeMillis()
                            )
                        )
                        messageText = ""
                    }
                }
            ) {
                Text("Send 🚀")
            }
        }
    }
}

fun generateQrBitmap(content: String, size: Int): Bitmap? {
    return try {
        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, size, size)
        val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
        for (x in 0 until size) {
            for (y in 0 until size) {
                bitmap.setPixel(x, y, if (bitMatrix.get(x, y)) Color.BLACK else Color.WHITE)
            }
        }
        bitmap
    } catch (_: Exception) {
        null
    }
}

