// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import SwiftUI
import YubiKit

@MainActor
final class ConnectionManager: ObservableObject {

    static let shared = ConnectionManager()

    @Published private(set) var wiredConnection: SmartCardConnection?
    @Published private(set) var currentTokenInstanceID: String?
    #if os(iOS)
    @Published private(set) var nfcConnection: NFCSmartCardConnection?
    #endif

    @Published var error: Error?

    private var wiredConnectionTask: Task<Void, Never>?

    private init() {
        startWiredConnection()
    }

    private func startWiredConnection() {
        wiredConnectionTask = Task { @MainActor in
            while !Task.isCancelled {
                do {
                    error = nil
                    guard !Task.isCancelled else { return }

//                    let newConnection = try await WiredSmartCardConnection.makeConnection()
//                    guard !Task.isCancelled else { return }
//
//                    wiredConnection = newConnection
//                    
//                    // Register the token when YubiKey connects
////                    await registerToken(connection: newConnection)
//
//                    let closeError = await newConnection.waitUntilClosed()

                    // Unregister the token when YubiKey disconnects
//                    await unregisterCurrentToken()
                    
//                    wiredConnection = nil

//                    if let closeError = closeError {
//                        error = closeError
//                    }
                } catch {
                    self.error = error
                }
            }
        }
    }
    
    // MARK: - Token Registration
    
//    private func registerToken(connection: SmartCardConnection) async {
//        do {
//            let pivSession = try await PIVSession.makeSession(connection: connection)
//            
//            // Get the CHUID for token identification
//            guard let chuid = try await pivSession.getCHUID() else {
//                print("ConnectionManager: No CHUID found, skipping token registration")
//                return
//            }
//            
//            // Collect certificates from all PIV slots
//            var certificates: [PIVSlotCertificate] = []
//            
//            for slot in Self.pivSlots {
//                do {
//                    let cert = try await pivSession.getCertificate(in: slot)
//                    
//                    if let secCert = SecCertificateCreateWithData(nil, cert.der as CFData) {
//                        let summary = SecCertificateCopySubjectSummary(secCert) as String? ?? "Certificate"
//                        let label = "\(summary) (\(slotName(for: slot)))"
//                        
//                        certificates.append(PIVSlotCertificate(
//                            slot: slot,
//                            certificate: secCert,
//                            derData: cert.der,
//                            label: label
//                        ))
//                    }
//                } catch {
//                    // Slot doesn't have a certificate, continue to next
//                }
//            }
//            
//            guard !certificates.isEmpty else {
//                print("ConnectionManager: No certificates found, skipping token registration")
//                return
//            }
//            
//            // Store the token data (the extension will use this when the system requests the token)
//            let instanceID = TokenDriver.instanceID(forCHUID: chuid)
//            TokenDriver.shared.storeTokenData(
//                instanceID: instanceID,
//                chuid: chuid,
//                certificates: certificates
//            )
//            
//            currentTokenInstanceID = instanceID
//            print("ConnectionManager: Stored token data with \(certificates.count) certificate(s)")
//            
//        } catch {
//            print("ConnectionManager: Failed to register token: \(error)")
//            self.error = error
//        }
//    }
//    
//    private func unregisterCurrentToken() async {
//        guard let instanceID = currentTokenInstanceID else { return }
//        
//        TokenDriver.shared.removeTokenData(instanceID: instanceID)
//        currentTokenInstanceID = nil
//        print("ConnectionManager: Removed token data")
//    }
    
    private static let pivSlots: [PIV.Slot] = [
        .authentication,
        .signature,
        .keyManagement,
        .cardAuth
    ]
    
    private func slotName(for slot: PIV.Slot) -> String {
        switch slot {
        case .authentication: return "Authentication"
        case .signature: return "Digital Signature"
        case .keyManagement: return "Key Management"
        case .cardAuth: return "Card Authentication"
        default: return "Slot 0x\(String(slot.rawValue, radix: 16))"
        }
    }

    #if os(iOS)
    func requestNFCConnection() async {
        error = nil

        do {
            nfcConnection = try await NFCSmartCardConnection()
        } catch {
            self.error = error
        }
    }

    func closeNFCConnection(message: String? = nil) async {
        error = nil

        await nfcConnection?.close(message: message)
    }
    #endif
}

extension SmartCardConnection {
    var connectionType: String {
        switch self {
        #if os(iOS)
        case _ as NFCSmartCardConnection:
            return "NFC"
        case _ as LightningSmartCardConnection:
            return "Lightning"
        #endif
        case _ as USBSmartCardConnection:
            return "USB"
        default:
            return "Unknown"
        }
    }
}

extension Optional where Wrapped == SmartCardConnection {
    var connectionType: String {
        guard let connection = self else {
            return "No Connection"
        }

        return connection.connectionType
    }
}
