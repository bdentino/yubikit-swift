/*
 * Copyright (C) 2022 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation
import CryptoTokenKit

struct TokenCertificateStorage {
    
    static let shared = TokenCertificateStorage()
    
    private static let driverConfigKey = "sh.bjd.Authenticator.TokenExtension"
    
    enum TokenCertificateStorageError: Error {
        case failedCreatingTokenKeychainCertificate
        case failedCreatingTokenKeychainKey
        case missingDriverConfiguration
        case missingCertificate
    }
    
    /// Safely gets the driver configuration, returning nil if not available
    /// This avoids blocking on CryptoTokenKit if the extension isn't properly set up
    private func getDriverConfiguration() -> TKTokenDriver.Configuration? {
        // Access driverConfigurations - this can sometimes block if there are issues
        let configs = TKTokenDriver.Configuration.driverConfigurations
        return configs[Self.driverConfigKey]
    }

    func storeTokenCertificate(tokenID: String, certificate: SecCertificate) -> Error? {
        let label = certificate.tokenObjectId()
        print("Certificate objectID: \(label)")
        guard let sha1 = certificate.publicKeyHash() else {
            return TokenCertificateStorageError.missingCertificate
        }
        let sha1str = sha1.map { String(format: "%02X", $0) }.joined()
        print("Public key hash: \(sha1str)")
        
        // Create token keychain certificate using the certificate and derived label
        guard let tokenKeychainCertificate = TKTokenKeychainCertificate(certificate: certificate, objectID: "cert:\(label)") else {
            return TokenCertificateStorageError.failedCreatingTokenKeychainCertificate
        }
        
        guard let tokenKeychainKey = TKTokenKeychainKey(certificate: certificate, objectID: "key:\(label)") else {
            return TokenCertificateStorageError.failedCreatingTokenKeychainKey
        }
        if let pkkh = tokenKeychainKey.publicKeyHash?.hexString {
            print("Public key hash: \(pkkh)")
        }
        tokenKeychainKey.canSign = true
        tokenKeychainKey.isSuitableForLogin = true
        tokenKeychainKey.canDecrypt = false
        tokenKeychainKey.constraints = [
            NSNumber(value: TKTokenOperation.signData.rawValue): "PIN"
        ]
        print("Key constraints: \(tokenKeychainKey.constraints?.description ?? "none")")
        
        guard let tokenDriverConfiguration = getDriverConfiguration() else {
            return TokenCertificateStorageError.missingDriverConfiguration
        }
        
        let tokenConfiguration = tokenDriverConfiguration.addTokenConfiguration(for: tokenID)
        tokenConfiguration.keychainItems.append(contentsOf: [tokenKeychainCertificate, tokenKeychainKey])

        return nil
    }
    
    func getTokenCertificate(withObjectId objectId: String) -> SecCertificate? {
        let certificates = listTokenCertificates()
        return certificates.first { certificate in
            return certificate.tokenObjectId() == objectId
        }
    }
    
    func listTokenCertificates() -> [SecCertificate] {
        guard let tokenDriverConfiguration = getDriverConfiguration() else {
            return [SecCertificate]()
        }
        
        let certificates = tokenDriverConfiguration.tokenConfigurations
            .map { $0.value }
            .flatMap { $0.keychainItems }
            .compactMap { $0 as? TKTokenKeychainCertificate }
            .map { SecCertificateCreateWithData(nil, $0.data as CFData) }
            .compactMap { $0 }
            .sorted { $0.commonName ?? "" < $1.commonName ?? "" }
        
        return certificates
    }

    func removeTokenCertificate(tokenID: String, certificate: SecCertificate) -> Bool {
        guard let tokenDriverConfiguration = getDriverConfiguration() else {
            return false
        }
        
        tokenDriverConfiguration.tokenConfigurations[tokenID]?.keychainItems.removeAll()
        return true
    }
}
