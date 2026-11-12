import SwiftUI
import CoreImage.CIFilterBuiltins

/// Task 6: Native iOS UI Skeleton (SwiftUI)
///
/// Views:
/// - OnboardingView: Friend Code Fingerprint + QR Code generator
/// - ChatListView: Stored contacts + TTL indicators
/// - ChatView: Encrypted message timeline, send controls, and Disappearing Messages TTL selector
/// - SafetyNumberView: 12-group 60-digit verification dialog

struct ContentView: View {
    @State private var selectedTab = 0
    let myFriendCode = IdentityManager.shared.friendCode()

    var body: some View {
        TabView(selection: $selectedTab) {
            OnboardingView(friendCode: myFriendCode)
                .tabItem {
                    Label("Identity", systemImage: "key.fill")
                }
                .tag(0)

            ChatListView()
                .tabItem {
                    Label("Chats", systemImage: "message.fill")
                }
                .tag(1)
        }
        .preferredColorScheme(.dark)
        .accentColor(Color(red: 0.0, green: 0.82, blue: 0.71))
    }
}

struct OnboardingView: View {
    let friendCode: String

    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                Spacer()

                Text("Anonymous Identity")
                    .font(.title2)
                    .fontWeight(.bold)

                Text("No phone. No email. 100% Tor routed.")
                    .font(.subheadline)
                    .foregroundColor(.secondary)

                if let qrImage = generateQRCode(from: friendCode) {
                    Image(uiImage: qrImage)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 220, height: 220)
                        .padding()
                        .background(Color.white)
                        .cornerRadius(16)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Friend Code:")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(friendCode)
                        .font(.system(.caption, design: .monospaced))
                        .padding(10)
                        .background(Color(white: 0.15))
                        .cornerRadius(8)
                }
                .padding(.horizontal)

                Button(action: {
                    UIPasteboard.general.string = friendCode
                }) {
                    Label("Copy Friend Code", systemImage: "doc.on.doc")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color(red: 0.0, green: 0.82, blue: 0.71))
                        .foregroundColor(.black)
                        .cornerRadius(12)
                }
                .padding(.horizontal)

                Spacer()
            }
            .navigationTitle("AnonChat")
        }
    }

    func generateQRCode(from string: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.setValue(Data(string.utf8), forKey: "inputMessage")
        guard let outputImage = filter.outputImage else { return nil }
        let context = CIContext()
        if let cgImage = context.createCGImage(outputImage, from: outputImage.extent) {
            return UIImage(cgImage: cgImage)
        }
        return nil
    }
}

struct ChatListView: View {
    var body: some View {
        NavigationView {
            List {
                NavigationLink(destination: ChatView(contactName: "Bob", contactUserId: "user-bob-123")) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Bob")
                                .font(.headline)
                            Text("Session established via X3DH & Tor")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Text("⏳ 24h")
                            .font(.caption2)
                            .padding(4)
                            .background(Color.blue.opacity(0.3))
                            .cornerRadius(4)
                    }
                }
            }
            .navigationTitle("Encrypted Chats")
        }
    }
}

struct ChatView: View {
    let contactName: String
    let contactUserId: String

    @State private var messageText = ""
    @State private var ttlHours = 24
    @State private var showSafetyNumber = false
    @State private var messages: [String] = [
        "Session verified. Traffic routed over Tor SOCKS5.",
        "Messages are padded to fixed 4KB blocks before encryption."
    ]

    var body: some View {
        VStack {
            // Header Bar with Safety Number and TTL selector
            HStack {
                Button(action: { showSafetyNumber = true }) {
                    Label("Safety Code", systemImage: "checkmark.shield.fill")
                        .font(.caption)
                }

                Spacer()

                Menu {
                    Button("TTL: Off") { ttlHours = 0 }
                    Button("TTL: 1 Hour") { ttlHours = 1 }
                    Button("TTL: 24 Hours") { ttlHours = 24 }
                    Button("TTL: 7 Days") { ttlHours = 168 }
                } label: {
                    Text(ttlHours > 0 ? "⏳ \(ttlHours)h TTL" : "⏳ Off")
                        .font(.caption)
                        .padding(6)
                        .background(Color(white: 0.2))
                        .cornerRadius(6)
                }
            }
            .padding(.horizontal)

            Divider()

            // Timeline
            ScrollView {
                VStack(alignment: .trailing, spacing: 8) {
                    ForEach(messages, id: \.self) { msg in
                        HStack {
                            Spacer()
                            Text(msg)
                                .padding(12)
                                .background(Color(red: 0.0, green: 0.35, blue: 0.55))
                                .foregroundColor(.white)
                                .cornerRadius(14)
                        }
                    }
                }
                .padding()
            }

            // Input Bar
            HStack {
                TextField("Encrypted message...", text: $messageText)
                    .textFieldStyle(RoundedBorderTextFieldStyle())

                Button(action: {
                    if !messageText.isEmpty {
                        messages.append(messageText)
                        messageText = ""
                    }
                }) {
                    Image(systemName: "paperplane.fill")
                        .foregroundColor(Color(red: 0.0, green: 0.82, blue: 0.71))
                }
            }
            .padding()
        }
        .navigationTitle(contactName)
        .sheet(isPresented: $showSafetyNumber) {
            SafetyNumberView(contactName: contactName, contactUserId: contactUserId)
        }
    }
}

struct SafetyNumberView: View {
    let contactName: String
    let contactUserId: String

    var safetyNumber: String {
        let myKey = IdentityManager.shared.identityPublicKey.rawRepresentation
        let remoteKey = Data(repeating: 0x42, count: 32) // Simulated remote key
        return SafetyNumber.generateCompositeSafetyNumber(
            localIdentityKey: myKey,
            localIdentifier: IdentityManager.shared.userId(),
            remoteIdentityKey: remoteKey,
            remoteIdentifier: contactUserId
        )
    }

    var body: some View {
        VStack(spacing: 20) {
            Text("Safety Number Verification")
                .font(.title3)
                .fontWeight(.bold)

            Text("Verify that this 60-digit number matches the code on \(contactName)'s device:")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Text(safetyNumber)
                .font(.system(.body, design: .monospaced))
                .fontWeight(.bold)
                .foregroundColor(Color(red: 1.0, green: 0.72, blue: 0.3))
                .multilineTextAlignment(.center)
                .padding()
                .background(Color(white: 0.1))
                .cornerRadius(10)
                .padding(.horizontal)

            Button("Mark as Verified ✓") {
                // Stores verified state in local encrypted database
            }
            .buttonStyle(.borderedProminent)
            .tint(Color(red: 0.0, green: 0.82, blue: 0.71))
        }
        .padding()
    }
}

