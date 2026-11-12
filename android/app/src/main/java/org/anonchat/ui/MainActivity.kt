package org.anonchat.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import org.anonchat.crypto.IdentityKeyManager

class MainActivity : ComponentActivity() {
    private lateinit var identityManager: IdentityKeyManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Generate or load cryptographic identity from hardware-backed Android Keystore
        identityManager = IdentityKeyManager()
        val myFriendCode = identityManager.getFriendCode()

        setContent {
            MaterialTheme {
                Surface(color = MaterialTheme.colorScheme.background) {
                    AnonChatAppScreen(myFriendCode = myFriendCode)
                }
            }
        }
    }
}

