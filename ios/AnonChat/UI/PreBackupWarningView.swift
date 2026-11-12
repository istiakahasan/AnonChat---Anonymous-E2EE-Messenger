import SwiftUI

/// Mandatory Pre-Backup Warning Screen (iOS SwiftUI)
///
/// Security & UI Requirements:
/// 1. Header: "Your backup is yours alone"
/// 2. Body text: "If you lose your passphrase, your backup cannot be recovered. No one, including us, can help you. We do not have a copy of your key."
/// 3. Secondary text: "This is not a limitation. It is what makes your backup private. If we could recover it, so could anyone who compromises our servers."
/// 4. Required action: Checkbox: "I understand that if I lose my passphrase, my backup is permanently lost."
/// 5. Continue button: Disabled until the checkbox is checked.
/// 6. Strictly NO bypass: No "Skip" or "Remind me later" buttons.
struct PreBackupWarningView: View {
    let onContinue: () -> Void
    var onCancel: (() -> Void)? = nil

    @State private var acknowledged = false

    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                // Warning Shield Icon
                Image(systemName: "shield.lefthalf.filled")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 60, height: 60)
                    .foregroundColor(Color.red)
                    .padding()
                    .background(Color.red.opacity(0.12))
                    .clipShape(Circle())
                    .padding(.top, 20)

                // 1. Header
                Text("Your backup is yours alone")
                    .font(.title2)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
                    .multilineTextAlignment(.center)

                // 2. Body Text (exact wording)
                VStack(alignment: .leading) {
                    Text("If you lose your passphrase, your backup cannot be recovered. No one, including us, can help you. We do not have a copy of your key.")
                        .font(.body)
                        .fontWeight(.semibold)
                        .foregroundColor(Color(white: 0.95))
                        .padding()
                }
                .frame(maxWidth: .infinity)
                .background(Color(white: 0.12))
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.red.opacity(0.4), lineWidth: 1)
                )

                // 3. Secondary Text (exact wording)
                Text("This is not a limitation. It is what makes your backup private. If we could recover it, so could anyone who compromises our servers.")
                    .font(.subheadline)
                    .foregroundColor(Color(white: 0.7))
                    .multilineTextAlignment(.leading)

                Spacer()

                // 4. Required Action: Checkbox
                Button(action: {
                    acknowledged.toggle()
                }) {
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: acknowledged ? "checkmark.square.fill" : "square")
                            .resizable()
                            .frame(width: 22, height: 22)
                            .foregroundColor(acknowledged ? Color(red: 0.0, green: 0.82, blue: 0.71) : .gray)

                        Text("I understand that if I lose my passphrase, my backup is permanently lost.")
                            .font(.subheadline)
                            .fontWeight(.medium)
                            .foregroundColor(.white)
                            .multilineTextAlignment(.leading)
                    }
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(white: 0.1))
                    .cornerRadius(12)
                }

                // 5. Continue button: Disabled until the checkbox is checked
                Button(action: {
                    if acknowledged {
                        onContinue()
                    }
                }) {
                    Text("Continue")
                        .font(.headline)
                        .fontWeight(.bold)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(acknowledged ? Color(red: 0.0, green: 0.82, blue: 0.71) : Color(white: 0.2))
                        .foregroundColor(acknowledged ? .black : .gray)
                        .cornerRadius(12)
                }
                .disabled(!acknowledged)
            }
            .padding(24)
            .background(Color.black.edgesIgnoringSafeArea(.all))
            .navigationBarItems(
                leading: Button("Cancel") {
                    acknowledged = false
                    onCancel?()
                }
                .foregroundColor(.gray)
            )
        }
    }
}

