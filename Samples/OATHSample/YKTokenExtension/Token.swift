//
//  Token.swift
//  YKTokenExtension
//
//  Created by Brian Dentino on 1/28/26.
//

import CryptoTokenKit
import YubiKit
import X509
import SwiftASN1
import OSLog

public class Token: TKSmartCardToken, TKTokenDelegate {
    override weak public var delegate: TKTokenDelegate? {
        get { return self }
        set { }
    }
    
    public func createSession(_ token: TKToken) throws -> TKTokenSession {
        os_log(.debug, log: log, "Requesting new session for token %{public}@", token.configuration.instanceID)
        return TokenSession(token: token)
    }
    
    public func token(_ token: TKToken, terminateSession: TKTokenSession) {
        os_log(.debug, log: log, "Asking to terminate session for token %{public}@", token.configuration.instanceID)
    }
    
    func loadKeychainContents(session: PIVSession) async throws {
        var items: [TKTokenKeychainItem] = []
        for slot in PIV.Slot.allCases {
            do {
                let (tokenKeychainCertificate, tokenKeychainKey) = try await session.tokenKeychainItems(inSlot: slot)
                items.append(contentsOf: [tokenKeychainCertificate, tokenKeychainKey])
            } catch {
                os_log(.error, log: log, "Failed to read slot %{public}x: %{public}@", slot.rawValue, error.localizedDescription)
            }
        }
        
        os_log(.debug, log: log, "Loaded %{public}d keychain items from token %{public}@", items.count, self.configuration.instanceID)
        
        self.keychainContents?.fill(with: items)
    }
}
