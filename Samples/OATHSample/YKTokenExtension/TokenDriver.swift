//
//  TokenDriver.swift
//  YKTokenExtension
//
//  Created by Brian Dentino on 1/28/26.
//

import CryptoTokenKit
import YubiKit
import OSLog

let log = OSLog(subsystem: "sh.bjd.Authenticator.TokenExtension", category: "debug")

public class TokenDriver: TKSmartCardTokenDriver, TKSmartCardTokenDriverDelegate {

    override weak public var delegate: TKTokenDriverDelegate? {
        get { return self }
        set { }
    }
    
    public func tokenDriver(_ driver: TKTokenDriver, terminateToken token: TKToken) {
        os_log(.debug, log: log, "Got request to terminate token %{public}@", token.configuration.instanceID)
        try? deleteCachedPIN(for: token.configuration.instanceID)
    }
    
    public func tokenDriver(_ driver: TKTokenDriver, tokenFor configuration: TKToken.Configuration) throws -> TKToken {
        os_log(.debug, log: log, "Got request for persistent token %{public}@", configuration.instanceID)
        throw TKError(.tokenNotFound)
    }
    
    public func tokenDriver(
        _ driver: TKSmartCardTokenDriver,
        createTokenFor smartCard: TKSmartCard,
        aid AID: Data?
    ) throws -> TKSmartCardToken {
        os_log(.debug, log: log, "Got request for token on smartcard %{public}@ in slot %{public}@ for aid %{public}@",
               smartCard.description,
               smartCard.slot.name,
               AID?.hexString ?? "nil")
        
        let serialNo = try TokenDriver.getSerialNumber(
            fromSmartCard: smartCard,
            inSlot: smartCard.slot.name
        )
        os_log(.debug, log: log, "Got card serial number: %{public}@", serialNo)
        
        let token = Token(
            smartCard: smartCard,
            aid: AID,
            instanceID: serialNo,
            tokenDriver: driver
        )
        
        try self.setupToken(token: token, forCard: smartCard)
        
        os_log(.debug, log: log, "Created token with instanceID %{public}@", token.configuration.instanceID)
        return token
    }
    
    static private func getSerialNumber(
        fromSmartCard smartCard: TKSmartCard,
        inSlot slot: String
    ) throws -> String {
        return try PIVSession.withSession(onCard: smartCard) { session in
            let serial = try await session.getSerialNumber()
            return String(serial, radix: 10)
        }
    }

    private func setupToken(token: Token, forCard smartCard: TKSmartCard) throws {
        try PIVSession.withSession(onCard: smartCard) { session in
            try await token.loadKeychainContents(session: session)
        }
    }
}
