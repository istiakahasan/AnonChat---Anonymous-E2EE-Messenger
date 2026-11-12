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
data class MessageItem(
    val id: String,
    val senderId: String,
    val isMine: Boolean,
    val text: String,
    val timestamp: Long,
    val isSystemWarning: Boolean = false
)

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
    var hasKeyChangeLock by remember { mutableStateOf(false) }
    var showKeyChangeDialog by remember { mutableStateOf(false) }
    var showAcceptWarningDialog by remember { mutableStateOf(false) }

    val messages = remember {
        mutableStateListOf(
            MessageItem("1", contact.userId, false, "Hello! Connected via X3DH & Tor.", System.currentTimeMillis() - 60000),
            MessageItem("2", "me", true, "Verified. Messages are padded to 4KB.", System.currentTimeMillis() - 30000)
        )
    }

    fun triggerKeyChange() {
        val warning = "⚠️ ${contact.nickname}'s security code has changed. This could mean they reinstalled the app, or someone is intercepting your messages. Tap to verify again."
        if (messages.none { it.isSystemWarning }) {
            messages.add(
                MessageItem(
                    id = "keychange_${System.currentTimeMillis()}",
                    senderId = "system",
                    isMine = false,
                    text = warning,
                    timestamp = System.currentTimeMillis(),
                    isSystemWarning = true
                )
            )
        }
        hasKeyChangeLock = true
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

            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = { triggerKeyChange() }) {
                    Text("⚡ Test Key Change", fontSize = 11.sp)
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
        }

        // Timeline
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(8.dp),
            reverseLayout = false
        ) {
            items(messages) { msg ->
                if (msg.isSystemWarning) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 6.dp)
                            .background(androidx.compose.ui.graphics.Color(0xFF332005), RoundedCornerShape(12.dp))
                            .clickable { showKeyChangeDialog = true }
                            .padding(14.dp)
                    ) {
                        Column {
                            Text("SECURITY CODE CHANGED", fontWeight = FontWeight.Bold, color = androidx.compose.ui.graphics.Color(0xFFFFB74D), fontSize = 12.sp)
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(msg.text, color = androidx.compose.ui.graphics.Color.White, fontSize = 13.sp)
                            Spacer(modifier = Modifier.height(6.dp))
                            Text("Tap to verify or resolve →", color = androidx.compose.ui.graphics.Color(0xFF00D2B4), fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }
                } else {
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
        }

        // Input bar (DISABLED while hasKeyChangeLock is true)
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
                enabled = !hasKeyChangeLock,
                placeholder = {
                    Text(
                        if (hasKeyChangeLock) "🚫 Input disabled: Tap security warning above to verify"
                        else "Encrypted message..."
                    )
                }
            )
            Spacer(modifier = Modifier.width(8.dp))
            Button(
                enabled = !hasKeyChangeLock,
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
                Text(if (hasKeyChangeLock) "Blocked 🚫" else "Send 🚀")
            }
        }
    }

    if (showKeyChangeDialog) {
        AlertDialog(
            onDismissRequest = { showKeyChangeDialog = false },
            title = { Text("Security Code Changed") },
            text = {
                Text(
                    "The cryptographic identity for ${contact.nickname} has changed.\n\n" +
                    "This could mean they reinstalled the app, or someone is intercepting your messages (Man-in-the-Middle attack).\n\n" +
                    "Messaging is LOCKED until you resolve this warning."
                )
            },
            confirmButton = {
                Button(onClick = {
                    // Option A: Verification succeeded
                    hasKeyChangeLock = false
                    showKeyChangeDialog = false
                }) {
                    Text("Verify Again (Numbers Match)")
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    showKeyChangeDialog = false
                    showAcceptWarningDialog = true
                }) {
                    Text("Accept New Key (Without Verification)", color = androidx.compose.ui.graphics.Color.Red)
                }
            }
        )
    }

    if (showAcceptWarningDialog) {
        AlertDialog(
            onDismissRequest = { showAcceptWarningDialog = false },
            title = { Text("Warning: Accept Without Verification?") },
            text = {
                Text(
                    "You are accepting a new security code for ${contact.nickname} without verifying it.\n\n" +
                    "If someone is intercepting your connection (MITM), they will be able to read and modify your messages.\n\n" +
                    "Are you sure you want to proceed?"
                )
            },
            confirmButton = {
                Button(
                    colors = ButtonDefaults.buttonColors(containerColor = androidx.compose.ui.graphics.Color.Red),
                    onClick = {
                        hasKeyChangeLock = false
                        showAcceptWarningDialog = false
                    }
                ) {
                    Text("Accept Without Verification")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAcceptWarningDialog = false }) {
                    Text("Cancel")
                }
            }
        )
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

/**
 * Mandatory Pre-Backup Warning Screen (Android Jetpack Compose)
 *
 * Requirements:
 * 1. Header: "Your backup is yours alone"
 * 2. Body text: "If you lose your passphrase, your backup cannot be recovered. No one, including us, can help you. We do not have a copy of your key."
 * 3. Secondary text: "This is not a limitation. It is what makes your backup private. If we could recover it, so could anyone who compromises our servers."
 * 4. Required action: Checkbox: "I understand that if I lose my passphrase, my backup is permanently lost."
 * 5. Continue button: Disabled until the checkbox is checked.
 * 6. Strictly NO bypass: No "Skip" or "Remind me later" options.
 */
@Composable
fun PreBackupWarningScreen(
    onContinue: () -> Unit,
    onCancel: () -> Unit
) {
    var acknowledged by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(androidx.compose.ui.graphics.Color(0xFF121212))
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.SpaceBetween
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start
            ) {
                TextButton(onClick = {
                    acknowledged = false
                    onCancel()
                }) {
                    Text("Cancel", color = androidx.compose.ui.graphics.Color.Gray)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // 1. Header
            Text(
                text = "Your backup is yours alone",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = androidx.compose.ui.graphics.Color.White
            )

            Spacer(modifier = Modifier.height(20.dp))

            // 2. Body Text (exact wording)
            Surface(
                color = androidx.compose.ui.graphics.Color(0xFF1E1E1E),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "If you lose your passphrase, your backup cannot be recovered. No one, including us, can help you. We do not have a copy of your key.",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = androidx.compose.ui.graphics.Color(0xFFF5F5F5),
                    modifier = Modifier.padding(16.dp)
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // 3. Secondary Text (exact wording)
            Text(
                text = "This is not a limitation. It is what makes your backup private. If we could recover it, so could anyone who compromises our servers.",
                fontSize = 14.sp,
                color = androidx.compose.ui.graphics.Color(0xFFAAAAAA),
                lineHeight = 20.sp
            )
        }

        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // 4. Required action: Checkbox
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(androidx.compose.ui.graphics.Color(0xFF1A1A1A), RoundedCornerShape(12.dp))
                    .clickable { acknowledged = !acknowledged }
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Checkbox(
                    checked = acknowledged,
                    onCheckedChange = { acknowledged = it },
                    colors = CheckboxDefaults.colors(
                        checkedColor = androidx.compose.ui.graphics.Color(0xFF00D2B4),
                        uncheckedColor = androidx.compose.ui.graphics.Color.Gray
                    )
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "I understand that if I lose my passphrase, my backup is permanently lost.",
                    fontSize = 14.sp,
                    color = androidx.compose.ui.graphics.Color.White,
                    fontWeight = FontWeight.Medium
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // 5. Continue button: Disabled until the checkbox is checked
            Button(
                onClick = onContinue,
                enabled = acknowledged,
                colors = ButtonDefaults.buttonColors(
                    containerColor = androidx.compose.ui.graphics.Color(0xFF00D2B4),
                    contentColor = androidx.compose.ui.graphics.Color.Black,
                    disabledContainerColor = androidx.compose.ui.graphics.Color(0xFF262626),
                    disabledContentColor = androidx.compose.ui.graphics.Color(0xFF555555)
                ),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
            ) {
                Text(
                    text = "Continue",
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp
                )
            }
        }
    }
}


