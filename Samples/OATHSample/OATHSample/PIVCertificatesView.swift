// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import SwiftUI
import YubiKit
import X509
import CryptoKit
import CryptoTokenKit

struct PIVCertificatesView: View {
    @StateObject private var connectionManager = ConnectionManager.shared
    @State private var certificates: [PIVCertificateInfo] = []
    @State private var isLoading = false
    @State private var error: Error? = nil
    @State private var showCopiedToast = false
    @State private var currentTokenID: String? = nil
    @State private var tokenStorage = TokenCertificateStorage.shared

    var body: some View {
        let isConnected = connectionManager.wiredConnection != nil
        NavigationStack {
            List {
                if !isConnected {
                    VStack(spacing: 20) {
                        Image(systemName: "key.icloud")
                            .font(.system(size: 60))
                            .foregroundColor(.secondary)
                        Text("Connect Your YubiKey")
                            .font(.title2)
                            .fontWeight(.semibold)
                        Text("Connect via USB to view PIV certificates on your YubiKey.")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 20)
                    }
                    .frame(maxWidth: .infinity, minHeight: 400)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                } else if isLoading {
                    ProgressView("Loading certificates...")
                        .frame(maxWidth: .infinity, minHeight: 400)
                        .listRowBackground(Color.clear)
                        .listRowInsets(EdgeInsets())
                } else if certificates.isEmpty {
                    VStack(spacing: 20) {
                        Image(systemName: "lock.slash")
                            .font(.system(size: 60))
                            .foregroundColor(.secondary)
                        Text("No Certificates Found")
                            .font(.title2)
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity, minHeight: 400)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                } else {
                    ForEach($certificates) { $cert in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(cert.label)
                                    .font(.body)
                                HStack(spacing: 4) {
                                    Button {
                                        copyToClipboard(cert.fingerprint)
                                        showCopiedToast = true
                                        Task {
                                            try? await Task.sleep(for: .seconds(2))
                                            showCopiedToast = false
                                        }
                                    } label: {
                                        Image(systemName: "doc.on.doc")
                                            .font(.caption2)
                                            .foregroundColor(.secondary)
                                    }
                                    .buttonStyle(.plain)
                                    Text(cert.fingerprint)
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                }
                                if let summary = cert.summary {
                                    Text(summary)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                if let keyUsage = cert.keyUsage {
                                    Text(keyUsage)
                                        .font(.caption2)
                                        .foregroundColor(.blue)
                                }
                            }
                            Spacer()
                            Toggle("", isOn: Binding(
                                get: { cert.isInKeychain },
                                set: { newValue in
                                    toggleCertificateInKeychain(cert: &cert, shouldAdd: newValue)
                                }
                            ))
                            .labelsHidden()
                        }
                        .padding(.vertical, 6)
                    }
                }
            }
            .navigationTitle("PIV Certificates")
            .onAppear {
                loadCertificatesIfNeeded()
                // Run diagnostics on a background thread to avoid blocking UI
                Task.detached(priority: .background) {
                    printCryptoTokenKitDiagnostics()
                }
            }
            .onChange(of: connectionManager.wiredConnection != nil) {
                loadCertificatesIfNeeded()
            }
            .alert(
                "Something went wrong",
                isPresented: Binding(
                    get: { error != nil },
                    set: { _ in error = nil }
                ),
                actions: {
                    Button("Ok", role: .cancel) {}
                },
                message: {
                    if let error = error {
                        Text("\(String(describing: error))")
                    }
                }
            )
            .overlay(alignment: .bottom) {
                if showCopiedToast {
                    Text("Copied to clipboard")
                        .font(.subheadline)
                        .fontWeight(.medium)
                        .foregroundColor(.white)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                        .background(Color.black.opacity(0.75))
                        .cornerRadius(8)
                        .padding(.bottom, 20)
                        .transition(.opacity.combined(with: .move(edge: .bottom)))
                        .animation(.easeInOut(duration: 0.3), value: showCopiedToast)
                }
            }
            .animation(.easeInOut(duration: 0.3), value: showCopiedToast)
        }
    }

    private func loadCertificatesIfNeeded() {
        guard let connection = connectionManager.wiredConnection else {
            certificates = []
            currentTokenID = nil
            return
        }
        isLoading = true
        error = nil
        Task {
            do {
                let pivSession = try await PIVSession.makeSession(connection: connection)
                guard let tokenID: String = try await pivSession.getCHUID() else {
                    throw NSError(domain: "PIVCertificatesView", code: -1, userInfo: nil)
                }
                currentTokenID = tokenID
                
                var loadedCerts: [PIVCertificateInfo] = []

                for slot in PIVCertificatesView.allRelevantPIVSlots {
                    do {
                        let cert = try await pivSession.getCertificate(in: slot)
                        let label = slot.rawValue
                        var subject = "No Subject"
                        var keyUsage: String? = nil
                        if let secCert = SecCertificateCreateWithData(nil, cert.der as CFData) {
                            if let summary = SecCertificateCopySubjectSummary(secCert) as String? {
                                subject = summary
                            }
                        }
                        keyUsage = parseKeyUsage(derData: cert.der)
                        let fingerprint = computeSHA1Fingerprint(derData: cert.der)
                        let isInKeychain = isCertificateInKeychain(derData: cert.der, tokenID: tokenID)
                        loadedCerts.append(.init(
                            label: "0x" + String(label, radix: 16),
                            summary: subject,
                            keyUsage: keyUsage,
                            fingerprint: fingerprint,
                            derData: cert.der,
                            isInKeychain: isInKeychain,
                            tokenID: tokenID,
                            id: UUID()
                        ))
                    } catch {
                        // Ignore errors for individual slots to continue loading others
                    }
                }

                certificates = loadedCerts
            } catch {
                certificates = []
                currentTokenID = nil
                self.error = error
            }
            isLoading = false
        }
    }

    private static let allRelevantPIVSlots: [PIV.Slot] = {
        var slots: [PIV.Slot] = [
            .authentication,
            .signature,
            .keyManagement,
            .cardAuth
        ]
        // Add retired slots 1 through 20
        for i in 1...20 {
            if let retiredSlot = PIV.Slot(rawValue: 0x81 + UInt8(i)) {
                slots.append(retiredSlot)
            }
        }
        return slots
    }()
    
    private func toggleCertificateInKeychain(cert: inout PIVCertificateInfo, shouldAdd: Bool) {
        if shouldAdd {
            let result = self.addCertificateToKeychain(derData: cert.derData, tokenID: cert.tokenID)
            if case .failure(let addError) = result {
                self.error = addError
            } else {
                cert.isInKeychain = true
            }
        } else {
            let result = self.removeCertificateFromKeychain(derData: cert.derData, tokenID: cert.tokenID)
            if case .failure(let removeError) = result {
                self.error = removeError
            } else {
                cert.isInKeychain = false
            }
        }
    }
    
    
    /// Checks if a certificate with the given DER data exists in the login keychain
    /// Note: This checks for certificates added to the login keychain (not hardware token items).
    private func isCertificateInKeychain(derData: Data, tokenID: String? = nil) -> Bool {
        guard let secCert = SecCertificateCreateWithData(nil, derData as CFData) else {
            return false
        }
        // Access storage synchronously but in a way that's safe for the current context
        // The actual check is fast since it's just a dictionary lookup
        let objectId = secCert.tokenObjectId()
        if self.tokenStorage.getTokenCertificate(withObjectId: objectId) != nil {
            return true
        }
        return false
    }

    /// Adds a certificate to the login keychain
    private func addCertificateToKeychain(derData: Data, tokenID: String) -> Result<Void, Error> {
        // Validate DER data is not empty
        guard !derData.isEmpty else {
            print("❌ Certificate DER data is empty")
            return .failure(KeychainError.invalidCertificateData)
        }
        print("✓ Certificate DER data size: \(derData.count) bytes")
        
        // Create SecCertificate
        guard let secCert = SecCertificateCreateWithData(nil, derData as CFData) else {
            print("❌ Failed to create SecCertificate from DER data")
            print("   First 32 bytes (hex): \(derData.prefix(32).map { String(format: "%02X", $0) }.joined(separator: " "))")
            return .failure(KeychainError.invalidCertificateData)
        }
        print("✓ SecCertificate created successfully")
        
        // Validate subject
        if let subject = SecCertificateCopySubjectSummary(secCert) as String? {
            print("✓ Certificate subject: \(subject)")
        } else {
            print("⚠️  Could not extract certificate subject")
        }
        
        // Validate public key can be extracted
        guard let publicKey = SecCertificateCopyKey(secCert) else {
            print("❌ Could not extract public key from certificate")
            return .failure(KeychainError.invalidCertificateData)
        }
        print("✓ Public key extracted successfully")
        
        // Get key type and size
        guard let keyAttributes = SecKeyCopyAttributes(publicKey) as? [CFString: Any] else {
            print("⚠️  Could not get public key attributes")
            return .failure(KeychainError.invalidCertificateData)
        }
        
        if let keyType = keyAttributes[kSecAttrKeyType] as? String {
            print("✓ Key type: \(keyType)")
        }
        if let keySize = keyAttributes[kSecAttrKeySizeInBits] as? Int {
            print("✓ Key size: \(keySize) bits")
        }
        
        // Validate certificate dates using Security framework
        var error: Unmanaged<CFError>?
        let certificateValues = SecCertificateCopyValues(secCert, [
            kSecOIDX509V1ValidityNotBefore,
            kSecOIDX509V1ValidityNotAfter
        ] as CFArray, &error)

        if let error = error?.takeRetainedValue() {
            print("⚠️  Could not get certificate validity dates: \(error)")
        } else if let values = certificateValues as? [CFString: Any] {
            if let notBeforeDict = values[kSecOIDX509V1ValidityNotBefore] as? [CFString: Any],
               let notBeforeValue = notBeforeDict[kSecPropertyKeyValue] as? NSNumber {
                let notBefore = Date(timeIntervalSinceReferenceDate: notBeforeValue.doubleValue)
                print("✓ Valid from: \(notBefore)")
            }
            
            if let notAfterDict = values[kSecOIDX509V1ValidityNotAfter] as? [CFString: Any],
               let notAfterValue = notAfterDict[kSecPropertyKeyValue] as? NSNumber {
                let notAfter = Date(timeIntervalSinceReferenceDate: notAfterValue.doubleValue)
                print("✓ Valid until: \(notAfter)")
                
                if notAfter < Date() {
                    print("⚠️  WARNING: Certificate is EXPIRED")
                }
            }
        }
        
        // Check extended key usage using openssl-style parsing
        let certData = SecCertificateCopyData(secCert) as Data
        print("✓ Certificate data re-exported: \(certData.count) bytes")
        
        // Verify SHA-256 hash
        let objectID = secCert.tokenObjectId()
        print("✓ Certificate objectID (SHA-256): \(objectID)")
        
        // Verify public key hash
        if let pubKeyHash = secCert.publicKeyHash() {
            let pubKeyHashStr = pubKeyHash.map { String(format: "%02X", $0) }.joined()
            print("✓ Public key hash (SHA-1): \(pubKeyHashStr)")
        } else {
            print("❌ Could not compute public key hash")
            return .failure(KeychainError.invalidCertificateData)
        }
        
        // All validation passed, store certificate
        print("📝 Attempting to store certificate in token...")
        if let error = self.tokenStorage.storeTokenCertificate(tokenID: tokenID, certificate: secCert) {
            print("❌ Failed to store certificate: \(error)")
            return .failure(error)
        } else {
            print("✅ Certificate stored successfully")
            return .success(())
        }
    }


    /// Removes a certificate from the login keychain
    /// Note: We don't filter by token ID when removing since we add certificates to the login keychain
    /// without a token ID (token IDs are system-managed for hardware token items).
    private func removeCertificateFromKeychain(derData: Data, tokenID: String) -> Result<Void, Error> {
        guard let secCert = SecCertificateCreateWithData(nil, derData as CFData) else {
            return .failure(KeychainError.invalidCertificateData)
        }
        
        if !self.tokenStorage.removeTokenCertificate(tokenID: tokenID, certificate: secCert) {
            return .failure(TokenCertificateStorage.TokenCertificateStorageError.missingCertificate)
        }
        
        return .success(())
    }
}

struct PIVCertificateInfo: Identifiable {
    var label: String
    var summary: String?
    var keyUsage: String?
    var fingerprint: String
    var derData: Data
    var isInKeychain: Bool
    var tokenID: String
    var id: UUID
}

// MARK: - Key Usage Parsing

func parseKeyUsage(derData: Data) -> String? {
    guard let certificate = try? Certificate(derEncoded: Array(derData)) else {
        return nil
    }
    
    var usages: [String] = []
    
    // Parse Key Usage extension
    if let keyUsageExtension = try? certificate.extensions.keyUsage {
        if keyUsageExtension.digitalSignature { usages.append("Digital Signature") }
        if keyUsageExtension.nonRepudiation { usages.append("Non-Repudiation") }
        if keyUsageExtension.keyEncipherment { usages.append("Key Encipherment") }
        if keyUsageExtension.dataEncipherment { usages.append("Data Encipherment") }
        if keyUsageExtension.keyAgreement { usages.append("Key Agreement") }
        if keyUsageExtension.keyCertSign { usages.append("Key Cert Sign") }
        if keyUsageExtension.cRLSign { usages.append("CRL Sign") }
        if keyUsageExtension.encipherOnly { usages.append("Encipher Only") }
        if keyUsageExtension.decipherOnly { usages.append("Decipher Only") }
    }
    
    // Parse Extended Key Usage extension
    if let extendedKeyUsage = try? certificate.extensions.extendedKeyUsage {
        for usage in extendedKeyUsage {
            usages.append(extendedKeyUsageDescription(for: usage))
        }
    }
    
    return usages.isEmpty ? nil : usages.joined(separator: ", ")
}

/// Returns a human-readable description for an Extended Key Usage OID
private func extendedKeyUsageDescription(for usage: ExtendedKeyUsage.Usage) -> String {
    switch usage {
    case .serverAuth:
        return "Server Authentication"
    case .clientAuth:
        return "Client Authentication"
    case .codeSigning:
        return "Code Signing"
    case .emailProtection:
        return "Email Protection"
    case .timeStamping:
        return "Time Stamping"
    case .ocspSigning:
        return "OCSP Signing"
    default:
        // For any other OID, return the OID string representation
        return "EKU: \(usage.description)"
    }
}

/// Computes the SHA-1 fingerprint of the certificate DER data
private func computeSHA1Fingerprint(derData: Data) -> String {
    let hash = Insecure.SHA1.hash(data: derData)
    return hash.map { String(format: "%02X", $0) }.joined(separator: "")
}

/// Copies the given string to the system clipboard
private func copyToClipboard(_ string: String) {
    #if os(macOS)
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(string, forType: .string)
    #else
    UIPasteboard.general.string = string
    #endif
}

/// Errors that can occur during keychain operations
enum KeychainError: LocalizedError {
    case invalidCertificateData
    case operationFailed(status: OSStatus)
    
    var errorDescription: String? {
        switch self {
        case .invalidCertificateData:
            return "Invalid certificate data"
        case .operationFailed(let status):
            if let message = SecCopyErrorMessageString(status, nil) as String? {
                return "Keychain operation failed: \(message)"
            }
            return "Keychain operation failed with status: \(status)"
        }
    }
}
// MARK: - CryptoTokenKit Diagnostics

/// Prints diagnostic information about all tokens and certificates visible to CryptoTokenKit
private func printCryptoTokenKitDiagnostics() {
    print("=== CryptoTokenKit Diagnostics ===")
    
    let tokenWatcher = TKTokenWatcher()
    let tokenIDs = tokenWatcher.tokenIDs
    
    print("Discovered \(tokenIDs.count) token(s):")
    
    if tokenIDs.isEmpty {
        print("  (No tokens found)")
        print("  Note: This could mean:")
        print("    - No smart card/YubiKey is connected")
        print("    - The device isn't recognized by CryptoTokenKit")
        print("    - Another application has an exclusive connection")
    }
    
    for tokenID in tokenIDs {
        print("\n  Token ID: \(tokenID)")
        
        // Query for all certificates associated with this token
        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrTokenID as String: tokenID,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true
        ]
        
        var certResult: CFTypeRef?
        let certStatus = SecItemCopyMatching(certQuery as CFDictionary, &certResult)
        
        if certStatus == errSecSuccess, let items = certResult as? [[String: Any]] {
            print("    Certificates (\(items.count)):")
            for (index, item) in items.enumerated() {
                if let certRef = item[kSecValueRef as String] {
                    let cert = certRef as! SecCertificate
                    let summary = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown"
                    print("      [\(index + 1)] \(summary)")
                    
                    // Print additional attributes if available
                    if let label = item[kSecAttrLabel as String] as? String {
                        print("          Label: \(label)")
                    }
                    if let serialNumber = item[kSecAttrSerialNumber as String] as? Data {
                        let serialHex = serialNumber.map { String(format: "%02X", $0) }.joined()
                        print("          Serial: \(serialHex)")
                    }
                }
            }
        } else if certStatus == errSecItemNotFound {
            print("    Certificates: None found")
        } else {
            print("    Certificates: Error querying (status: \(certStatus))")
        }
        
        // Query for all identities (certificate + private key pairs) associated with this token
        let identityQuery: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrTokenID as String: tokenID,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true
        ]
        
        var identityResult: CFTypeRef?
        let identityStatus = SecItemCopyMatching(identityQuery as CFDictionary, &identityResult)
        
        if identityStatus == errSecSuccess, let items = identityResult as? [[String: Any]] {
            print("    Identities (\(items.count)):")
            for (index, item) in items.enumerated() {
                if let identityRef = item[kSecValueRef as String] {
                    let identity = identityRef as! SecIdentity
                    var certRef: SecCertificate?
                    if SecIdentityCopyCertificate(identity, &certRef) == errSecSuccess, let cert = certRef {
                        let summary = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown"
                        print("      [\(index + 1)] \(summary)")
                    }
                }
            }
        } else if identityStatus == errSecItemNotFound {
            print("    Identities: None found")
        } else {
            print("    Identities: Error querying (status: \(identityStatus))")
        }
        
        // Query for all keys associated with this token
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrTokenID as String: tokenID,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true
        ]
        
        var keyResult: CFTypeRef?
        let keyStatus = SecItemCopyMatching(keyQuery as CFDictionary, &keyResult)
        
        if keyStatus == errSecSuccess, let items = keyResult as? [[String: Any]] {
            print("    Keys (\(items.count)):")
            for (index, item) in items.enumerated() {
                let label = item[kSecAttrLabel as String] as? String ?? "No label"
                var keyClassDescription = "Unknown"
                if let keyClassData = item[kSecAttrKeyClass as String] {
                    let keyClass = keyClassData as CFTypeRef
                    if CFEqual(keyClass, kSecAttrKeyClassPrivate) {
                        keyClassDescription = "Private"
                    } else if CFEqual(keyClass, kSecAttrKeyClassPublic) {
                        keyClassDescription = "Public"
                    } else if CFEqual(keyClass, kSecAttrKeyClassSymmetric) {
                        keyClassDescription = "Symmetric"
                    }
                }
                print("      [\(index + 1)] \(keyClassDescription) key - \(label)")
            }
        } else if keyStatus == errSecItemNotFound {
            print("    Keys: None found")
        } else {
            print("    Keys: Error querying (status: \(keyStatus))")
        }
    }
    
    // Also check the login keychain for any certificates (without token ID filter)
    print("\n  Login Keychain Certificates (non-token):")
    let loginKeychainQuery: [String: Any] = [
        kSecClass as String: kSecClassCertificate,
        kSecMatchLimit as String: kSecMatchLimitAll,
        kSecReturnRef as String: true,
        kSecReturnAttributes as String: true
    ]
    
    var loginResult: CFTypeRef?
    let loginStatus = SecItemCopyMatching(loginKeychainQuery as CFDictionary, &loginResult)
    
    if loginStatus == errSecSuccess, let items = loginResult as? [[String: Any]] {
        // Filter out token-based certificates
        let nonTokenCerts = items.filter { item in
            return item[kSecAttrTokenID as String] == nil
        }
        print("    Found \(nonTokenCerts.count) certificate(s) in login keychain:")
        for (index, item) in nonTokenCerts.prefix(10).enumerated() {
            if let certRef = item[kSecValueRef as String] {
                let cert = certRef as! SecCertificate
                let summary = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown"
                print("      [\(index + 1)] \(summary)")
            }
        }
        if nonTokenCerts.count > 10 {
            print("      ... and \(nonTokenCerts.count - 10) more")
        }
    } else if loginStatus == errSecItemNotFound {
        print("    No certificates in login keychain")
    } else {
        print("    Error querying login keychain (status: \(loginStatus))")
    }
    
    print("\n=== End Diagnostics ===\n")
}

