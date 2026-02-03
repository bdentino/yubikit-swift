//
//  TokenSession.swift
//  YKTokenExtension
//
//  Created by Brian Dentino on 1/28/26.
//

import CryptoTokenKit
import UserNotifications
import YubiKit
import OSLog
import CryptoKit

// TODO: Track pending auth requests so only one pin entry is required

class TokenSession: TKSmartCardTokenSession, TKTokenSessionDelegate {
    
    var uuid = UUID()
    
    override weak var delegate: TKTokenSessionDelegate? {
        get { return self }
        set { }
    }

    func tokenSession(
        _ session: TKTokenSession,
        beginAuthFor operation: TKTokenOperation,
        constraint: Any
    ) throws -> TKTokenAuthOperation {
        if let uuidSession = session as? TokenSession {
            os_log(.debug, log: log, "Beginning auth operation from session %{public}@", uuidSession.uuid.uuidString)
        }
        
        guard let smartCardSession = session as? TKSmartCardTokenSession,
              let smartCard = try? smartCardSession.getSmartCard() else {
            throw TKError(.tokenNotFound)
        }
        
        let instanceID = session.token.configuration.instanceID
        let authOperation = TokenSmartCardPINAuthOperation(forSmartCard: smartCard, withInstanceID: instanceID)
        return authOperation
    }
    
    func tokenSession(
        _ session: TKTokenSession,
        supports operation: TKTokenOperation,
        keyObjectID: Any,
        algorithm: TKTokenKeyAlgorithm
    ) -> Bool {
        if let uuidSession = session as? TokenSession {
            os_log(.debug, log: log, "Checking support for operation from session %{public}@", uuidSession.uuid.uuidString)
        }
        
        guard
            let smartCardSession = session as? TKSmartCardTokenSession,
            let keyID = keyObjectID as? String
        else {
            os_log(.error, log: log, "Rejecting support for operation because of invalid session or key id")
            return false
        }

        do {
            let result = try PIVSession.withSession(withinTokenSession: smartCardSession) { pivSession in
                try await supportsOperation(
                    operation,
                    keyID: keyID,
                    algorithm: algorithm,
                    pivSession: pivSession
                )
            }
            os_log(.debug, log: log, "Token key %{public}@ %{public}@ support operation", keyID, result ? "does" : "does not")
            return result
        } catch {
            os_log(.error, log: log, "Failed checking support of %{public}@ for operation with error %{public}@", keyID, error.localizedDescription)
            if let pivSessionError = error as? PIVSessionError,
               let responseStatus = pivSessionError.responseStatus {
                os_log(.error, log: log, "PIVSession failed with error %{public}@", responseStatus.status.description)
            }
            return false
        }
    }
    
    func tokenSession(
        _ session: TKTokenSession,
        sign dataToSign: Data,
        keyObjectID: Any,
        algorithm: TKTokenKeyAlgorithm
    ) throws -> Data {
        if let uuidSession = session as? TokenSession {
            os_log(.debug, log: log, "Requesting to sign data from session %{public}@ with %{public}@", uuidSession.uuid.uuidString, algorithm.description)
        }
        
        guard
            let oid = keyObjectID as? String,
            let smartCardSession = session as? TKSmartCardTokenSession
        else {
            throw TKError(TKError.tokenNotFound)
        }
        
        do {
            let result = try PIVSession.withSession(withinTokenSession: smartCardSession) { pivSession in
                guard let slot = try? await pivSession.getSlotID(forOID: oid),
                      let metadata = try? await pivSession.getMetadata(in: slot)
                else {
                    throw TKError(.objectNotFound)
                }
                guard let secKeyAlgorithm = algorithm.secKeyAlgorithm,
                      let pivAlgorithm = PIVAlgorithm(secKeyAlgorithm: secKeyAlgorithm)
                else {
                    throw TKError(.badParameter)
                }
                
                switch metadata.keyType {
                case .rsa(let keySize):
                    switch pivAlgorithm {
                    case .rsaSignature(let rsaAlg):
                        let signedData = try await pivSession.sign(
                            dataToSign,
                            in: slot,
                            keyType: PIV.RSAKey.rsa(keySize),
                            using: rsaAlg
                        )
                        return signedData
                    default:
                        throw TKError(.badParameter)
                    }
                case .ec(let curve):
                    switch pivAlgorithm {
                    case .ecdsaSignature(let ecAlg):
                        let signedData = try await pivSession.sign(
                            dataToSign,
                            in: slot,
                            keyType: PIV.ECKey.ec(curve),
                            using: ecAlg
                        )
                        return signedData
                    default:
                        throw TKError(.badParameter)
                    }
                default:
                    throw TKError(.badParameter)
                }
            }
            return result
        } catch {
            if let pivError = error as? PIVSessionError,
               case .failedResponse(let resp, _) = pivError,
               resp.status == .securityConditionNotSatisfied {
                throw TKError(.authenticationNeeded)
            }
            throw error
        }
    }
    
    func tokenSession(
        _ session: TKTokenSession,
        decrypt ciphertext: Data,
        keyObjectID: Any,
        algorithm: TKTokenKeyAlgorithm
    ) throws -> Data {
        if let uuidSession = session as? TokenSession {
            os_log(.debug, log: log, "Requesting to decrypt data from session %{public}@ with %{public}@", uuidSession.uuid.uuidString, algorithm.description)
        }
        
        guard
            let oid = keyObjectID as? String,
            let smartCardSession = session as? TKSmartCardTokenSession
        else {
            throw TKError(.tokenNotFound)
        }
        
        do {
            let result = try PIVSession.withSession(withinTokenSession: smartCardSession) { pivSession in
                guard let slot = try? await pivSession.getSlotID(forOID: oid),
                      let metadata = try? await pivSession.getMetadata(in: slot)
                else {
                    throw TKError(.objectNotFound)
                }
                guard let secKeyAlgorithm = algorithm.secKeyAlgorithm,
                      let pivAlgorithm = PIVAlgorithm(secKeyAlgorithm: secKeyAlgorithm)
                else {
                    throw TKError(.badParameter)
                }
                
                switch metadata.keyType {
                case .rsa(let keySize):
                    switch pivAlgorithm {
                    case .rsaEncryption(let rsaAlg):
                        let decryptedData = try await pivSession.decrypt(
                            ciphertext,
                            in: slot,
                            using: rsaAlg
                        )
                        return decryptedData
                    case .rsaEncryptionOAEPAESGCM(let hashAlgorithm):
                        // Hybrid encryption: RSA-OAEP wraps AES key, AES-GCM encrypts data
                        let wrappedKeyLength = keySize.bitCount / 8
                        guard ciphertext.count > wrappedKeyLength + 12 + 16 else {
                            throw TKError(.corruptedData)
                        }
                        
                        // Extract wrapped AES key
                        let wrappedKey = ciphertext.prefix(wrappedKeyLength)
                        
                        // YubiKey decrypts the wrapped AES key using RSA-OAEP with specified hash
                        let unwrappedAESKey = try await pivSession.decrypt(
                            wrappedKey,
                            in: slot,
                            using: hashAlgorithm.oaepAlgorithm
                        )
                        
                        // Extract IV, ciphertext, and auth tag
                        let remainingData = ciphertext.dropFirst(wrappedKeyLength)
                        let ivLength = 12
                        let tagLength = 16
                        
                        let iv = remainingData.prefix(ivLength)
                        let encryptedContent = remainingData.dropFirst(ivLength).dropLast(tagLength)
                        let tag = remainingData.suffix(tagLength)
                        
                        // Software AES-GCM decryption
                        let symmetricKey = SymmetricKey(data: unwrappedAESKey)
                        let nonce = try AES.GCM.Nonce(data: iv)
                        let sealedBox = try AES.GCM.SealedBox(
                            nonce: nonce,
                            ciphertext: encryptedContent,
                            tag: tag
                        )
                        let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
                        return decryptedData
                    default:
                        throw TKError(.badParameter)
                    }
                default:
                    throw TKError(.badParameter)
                }
            }
            return result
        } catch {
            if let pivError = error as? PIVSessionError,
               case .failedResponse(let resp, _) = pivError,
               resp.status == .securityConditionNotSatisfied {
                throw TKError(.authenticationNeeded)
            }
            throw error
        }
    }
    
    func tokenSession(
        _ session: TKTokenSession,
        performKeyExchange otherPartyPublicKeyData: Data,
        keyObjectID objectID: Any,
        algorithm: TKTokenKeyAlgorithm,
        parameters: TKTokenKeyExchangeParameters
    ) throws -> Data {
        if let uuidSession = session as? TokenSession {
            os_log(.debug, log: log, "Requesting key exchange from session %{public}@ with %{public}@", uuidSession.uuid.uuidString, algorithm.description)
        }
        
        guard
            let oid = objectID as? String,
            let smartCardSession = session as? TKSmartCardTokenSession
        else {
            throw TKError(.tokenNotFound)
        }
        
        do {
            let result = try PIVSession.withSession(withinTokenSession: smartCardSession) { pivSession in
                guard let slot = try? await pivSession.getSlotID(forOID: oid),
                      let metadata = try? await pivSession.getMetadata(in: slot)
                else {
                    throw TKError(.objectNotFound)
                }
                guard let secKeyAlgorithm = algorithm.secKeyAlgorithm,
                      let pivAlgorithm = PIVAlgorithm(secKeyAlgorithm: secKeyAlgorithm)
                else {
                    throw TKError(.badParameter)
                }
                
                switch metadata.keyType {
                case .ec(let curve):
                    guard case .ecdhKeyExchange(_, let kdf) = pivAlgorithm else {
                        throw TKError(.badParameter)
                    }
                    
                    // Parse the peer's public key from raw data
                    guard let peerPublicKey = EC.PublicKey(
                        uncompressedPoint: otherPartyPublicKeyData,
                        curve: curve
                    ) else {
                        throw TKError(.corruptedData)
                    }
                    
                    // Get raw shared secret from YubiKey
                    var sharedSecret = try await pivSession.deriveSharedSecret(
                        in: slot,
                        with: peerPublicKey
                    )
                    
                    // Apply X9.63 KDF if requested
                    if let kdf = kdf {
                        let requestedSize = parameters.requestedSize
                        sharedSecret = try applyX963KDF(
                            sharedSecret: sharedSecret,
                            sharedInfo: parameters.sharedInfo ?? Data(),
                            outputLength: requestedSize,
                            kdf: kdf
                        )
                    } else if parameters.requestedSize > 0,
                              sharedSecret.count > parameters.requestedSize {
                        // For raw ECDH, just truncate if needed
                        sharedSecret = Data(sharedSecret.prefix(parameters.requestedSize))
                    }
                    
                    return sharedSecret
                    
                case .x25519:
                    guard case .ecdhKeyExchange(_, let kdf) = pivAlgorithm else {
                        throw TKError(.badParameter)
                    }
                    
                    // Parse X25519 public key (32 bytes)
                    guard otherPartyPublicKeyData.count == 32,
                          let peerPublicKey = X25519.PublicKey(keyData: otherPartyPublicKeyData)
                    else {
                        throw TKError(.corruptedData)
                    }
                    
                    // Get raw shared secret from YubiKey
                    var sharedSecret = try await pivSession.deriveSharedSecret(
                        in: slot,
                        with: peerPublicKey
                    )
                    
                    // Apply X9.63 KDF if requested
                    if let kdf = kdf {
                        let requestedSize = parameters.requestedSize
                        sharedSecret = try applyX963KDF(
                            sharedSecret: sharedSecret,
                            sharedInfo: parameters.sharedInfo ?? Data(),
                            outputLength: requestedSize,
                            kdf: kdf
                        )
                    } else if parameters.requestedSize > 0,
                              sharedSecret.count > parameters.requestedSize {
                        sharedSecret = Data(sharedSecret.prefix(parameters.requestedSize))
                    }
                    
                    return sharedSecret
                    
                default:
                    throw TKError(.badParameter)
                }
            }
            return result
        } catch {
            if let pivError = error as? PIVSessionError,
               case .failedResponse(let resp, _) = pivError,
               resp.status == .securityConditionNotSatisfied {
                throw TKError(.authenticationNeeded)
            }
            throw error
        }
    }

}

private func supportsOperation(
    _ operation: TKTokenOperation,
    keyID: String,
    algorithm: TKTokenKeyAlgorithm,
    pivSession: PIVSession
) async throws -> Bool {
    let ykVersion = await pivSession.version
    os_log(.debug, log: log, "Checking if algorithm %{public}@ is supported by YubiKey version %{public}@", algorithm.description, ykVersion.description)
    guard algorithm.isSupportedByYubiKey(version: ykVersion) else { return false }
    
    os_log(.debug, log: log, "Looking up key to validate support", algorithm.description, ykVersion.description)
    guard let (_, key) = try await pivSession.getKeychainItems(forOID: keyID) else { return false }
    
    os_log(.debug, log: log, "Checking if key %{public}@ is supported by YubiKey version %{public}@", key.objectID as? String ?? "<unknown>", ykVersion.description)
    guard key.isSupportedByYubiKeyVersion(ykVersion) else { return false }
    
    os_log(.debug, log: log, "Checking if algorithm %{public}@ supports key type %{public}@", algorithm.description, key.keyType)
    guard algorithm.supportsKeyType(key.keyType) else { return false }
    
    os_log(.debug, log: log, "Checking whether key %{public}@ supports operation %{public}d", key.objectID as? String ?? "<unknown>", operation.rawValue)
    switch operation {
    case .readData:
        return true
    case .decryptData:
        return key.canDecrypt
    case .signData:
        return key.canSign
    case .performKeyExchange:
        return key.canPerformKeyExchange
    default:
        return false
    }
}

// X9.63 KDF implementation using CommonCrypto
private func applyX963KDF(
    sharedSecret: Data,
    sharedInfo: Data,
    outputLength: Int,
    kdf: PIVAlgorithm.ECDHKeyDerivation
) throws -> Data {
    var output = Data()
    var counter: UInt32 = 1
    
    while output.count < outputLength {
        var hashInput = Data()
        hashInput.append(sharedSecret)
        
        // Append counter as big-endian 32-bit integer
        var bigEndianCounter = counter.bigEndian
        hashInput.append(Data(bytes: &bigEndianCounter, count: 4))
        
        hashInput.append(sharedInfo)
        
        let hash = kdf.hash(data: hashInput)
        output.append(hash)
        counter += 1
        
        // Prevent infinite loop
        if counter > 1000 {
            throw TKError(.badParameter)
        }
    }
    
    return Data(output.prefix(outputLength))
}
