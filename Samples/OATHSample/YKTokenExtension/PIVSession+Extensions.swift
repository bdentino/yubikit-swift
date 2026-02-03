//
//  PIVSession+Extensions.swift
//  OATHSample
//
//  Created by Brian Dentino on 1/30/26.
//

import CryptoTokenKit
import YubiKit
import X509
import SwiftASN1
import OSLog

enum CertificateError: Error {
    case invalidDER
}

enum TokenKeychainError: Error {
    case invalidKeychainCertificate
    case invalidKeychainKey
}

extension PIVSession {
    @discardableResult
    public static func withSession<T: Sendable>(
        withinTokenSession session: TKSmartCardTokenSession,
        _ body: @escaping (PIVSession) async throws -> T
    ) throws -> T {
        let instance = session.token.configuration.instanceID
        guard let smartCard = try? session.getSmartCard() else { throw TKError(.tokenNotFound) }
        return try PIVSession.withSession(onCard: smartCard, forInstance: instance, body)
    }
    
    @discardableResult
    public static func withSession<T: Sendable>(
        onCard smartCard: TKSmartCard,
        _ body: @escaping (PIVSession) async throws -> T
    ) throws -> T {
        return try PIVSession.withSession(onCard: smartCard, forInstance: "", body)
    }
    
    @discardableResult
    public static func withSession<T: Sendable>(
        onCard smartCard: TKSmartCard,
        forInstance instanceID: String,
        _ body: @escaping (PIVSession) async throws -> T
    ) throws -> T {
        try smartCard.withSession {
            let resultBox = ResultBox<T>()
            let semaphore = DispatchSemaphore(value: 0)
            
            Task {
                let connection = SmartCardConnectionAdapter(card: smartCard)
                do {
                    let session = try await PIVSession.makeSession(connection: connection)
                    let result = try await body(session)
                    resultBox.set(.success(result))
                } catch {
                    if let pivError = error as? PIVSessionError,
                       case .failedResponse(let resp, _) = pivError,
                       resp.status == .securityConditionNotSatisfied,
                       !instanceID.isEmpty,
                       let pin = try? retrieveCachedPIN(for: instanceID),
                       !pin.isEmpty,
                       let session = try? await PIVSession.makeSession(connection: connection),
                       let verified = try? await session.verifyPin(pin),
                       verified == .success
                    {
                        do {
                            let retried = try await body(session)
                            resultBox.set(.success(retried))
                        } catch {
                            resultBox.set(.failure(error))
                        }
                    } else {
                        resultBox.set(.failure(error))
                    }
                }
                semaphore.signal()
            }
            
            semaphore.wait()
            return try resultBox.get()
        }
    }
    
    func tokenKeychainItems(inSlot slot: PIV.Slot) async throws -> (TKTokenKeychainCertificate, TKTokenKeychainKey) {
        let cert = try await self.getCertificate(in: slot)
        let metadata = try await self.getMetadata(in: slot)
        
        guard let secCert = SecCertificateCreateWithData(nil, cert.der as CFData),
              let x509 = try? Certificate(derEncoded: [UInt8](cert.der))
        else {
            throw CertificateError.invalidDER
        }
        
        let label = secCert.tokenObjectId()
        
        // Create token keychain certificate using the certificate and derived label
        guard let tokenKeychainCertificate = TKTokenKeychainCertificate(certificate: secCert, objectID: "cert:\(label)") else {
            throw TokenKeychainError.invalidKeychainCertificate
        }
        
        guard let tokenKeychainKey = TKTokenKeychainKey(certificate: secCert, objectID: "key:\(label)") else {
            throw TokenKeychainError.invalidKeychainKey
        }
        
        tokenKeychainKey.applyKeyUsage(fromCertificate: x509, forSlot: slot, withMetadata: metadata)
        
        return (tokenKeychainCertificate, tokenKeychainKey)
    }
    
    func getSlotID(forOID OID: String) async throws -> PIV.Slot? {
        for slot in PIV.Slot.allCases {
            do {
                let (_, key) = try await self.tokenKeychainItems(inSlot: slot)
                guard let objectID = key.objectID as? String else { continue }
                guard objectID == OID else { continue }
                return slot
            } catch {
                continue
            }
        }
        return nil
    }
    
    func getKeychainItems(forOID OID: String) async throws -> (TKTokenKeychainCertificate, TKTokenKeychainKey)? {
        if let slot = try? await self.getSlotID(forOID: OID) {
            let (cert, key) = try await self.tokenKeychainItems(inSlot: slot)
            return (cert, key)
        }
        return nil
    }
}

private final class ResultBox<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<T, Error>?
    
    func set(_ value: Result<T, Error>) {
        lock.lock()
        defer { lock.unlock() }
        result = value
    }
    
    func get() throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard let result = result else {
            fatalError("Result not set")
        }
        return try result.get()
    }
}

// TODO: Try to use YubiKit lifecycle management instead of custom adapter
/// Wraps TKSmartCard to work with YubiKit's SDK. Note that the PIVSession
/// class makes no attempt to manage the lifecycle of the connection, so we
/// only need a functional implementation of `send(data: Data)`
actor SmartCardConnectionAdapter: SmartCardConnection {
    let name: String
    private let card: TKSmartCard
    
    /// Creates an adapter wrapping an existing TKSmartCard
    init(card: TKSmartCard) {
        self.card = card
        self.name = card.slot.name
    }
    
    public init() async throws(YubiKit.SmartCardConnectionError) {
        throw .noDevicesFound
    }
    
    public static func makeConnection() async throws(YubiKit.SmartCardConnectionError) -> Self {
        throw .noDevicesFound
    }
    
    public func close(error: (any Error)?) async {
        
    }
    
    public func waitUntilClosed() async -> (any Error)? {
        return nil
    }
    
    public func send(data: Data) async throws(YubiKit.SmartCardConnectionError) -> Data {
        guard card.isValid else {
            throw SmartCardConnectionError.connectionLost
        }
        
        do {
            return try await card.transmit(data)
        } catch let error as SmartCardConnectionError {
            throw error
        } catch {
            throw SmartCardConnectionError.transmitFailed("USB transmit failed", error)
        }
    }
}
