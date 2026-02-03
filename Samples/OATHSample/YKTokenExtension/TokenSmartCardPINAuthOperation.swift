//
//  TokenSmartCardPINAuthOperation.swift
//  OATHSample
//
//  Created by Brian Dentino on 1/31/26.
//

import CryptoTokenKit
import LocalAuthentication

class TokenSmartCardPINAuthOperation: TKTokenSmartCardPINAuthOperation {
    let instanceID: String
    
    init(forSmartCard smartCard: TKSmartCard, withInstanceID instanceID: String) {
        self.instanceID = instanceID
        super.init()
        self.smartCard = smartCard
        self.setupPINFormat()
    }
    
    required init?(coder: NSCoder) {
        self.instanceID = coder.decodeObject(forKey: "instanceID") as! String
        super.init(coder: coder)
        self.setupPINFormat()
    }
    
    override func encode(with coder: NSCoder) {
        super.encode(with: coder)
        coder.encode(self.instanceID, forKey: "instanceID")
    }
    
    private func setupPINFormat() {
        // Configure PIN format for YubiKey PIV
        let pinFormat = TKSmartCardPINFormat()
        pinFormat.charset = .alphanumeric
        pinFormat.encoding = .ascii
        pinFormat.minPINLength = 6
        pinFormat.maxPINLength = 8
        pinFormat.pinJustification = .left
        pinFormat.pinBitOffset = 0
        pinFormat.pinBlockByteLength = 8
        pinFormat.pinLengthBitOffset = 0
        pinFormat.pinLengthBitSize = 0
        
        self.pinFormat = pinFormat
        self.pinByteOffset = 0
        self.apduTemplate = Data([
            0x00, 0x20, 0x00, 0x80, 0x08,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ])
    }
    
    override func finish() throws {
        guard let smartCard = self.smartCard else {
            throw TKError(.tokenNotFound)
        }
        
        var pin = self.pin ?? ""
        try smartCard.withSession {
            try super.finish()
        }
        
        // Check if PIN is available before attempting to cache
        if !pin.isEmpty && !self.instanceID.isEmpty {
            try? cachePINInSecureEnclave(pin, underID: self.instanceID)
            pin.removeAll()
        }
    }
}

func getKeychainID(forInstanceID id: String) -> String {
    return "sh.bjd.authenticator.scpin.\(id)"
}

func cachePINInSecureEnclave(_ pin: String, underID instanceID: String) throws {
    // Create LAContext for authentication
    let context = LAContext()
    context.localizedReason = "securely cache your PIN"
    context.localizedCancelTitle = "Cancel"
    
    // Optional: Customize the authentication UI
    #if os(iOS)
    context.localizedFallbackTitle = "Use Passcode"
    #endif
    
    // Create access control with secure local device & user presence requirement
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        .userPresence,
        nil
    ) else {
        throw TKError(.corruptedData)
    }
    
    // Convert PIN to Data
    guard let pinData = pin.data(using: .utf8) else {
        throw TKError(.corruptedData)
    }
    
    // Prepare keychain query
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: getKeychainID(forInstanceID: instanceID),
        kSecAttrService as String: "SmartCardPIN",
        kSecUseDataProtectionKeychain as String: true,
        kSecUseAuthenticationContext as String: context,
        kSecAttrSynchronizable as String: false,
        kSecAttrAccessControl as String: access,
        kSecAttrIsInvisible as String: true,
        kSecValueData as String: pinData,
    ]
    
    // Try to add the item
    var status = SecItemAdd(query as CFDictionary, nil)
    
    // If item already exists, update it
    if status == errSecDuplicateItem {
        let updateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: getKeychainID(forInstanceID: instanceID),
            kSecAttrService as String: "SmartCardPIN",
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecAttrSynchronizable as String: false,
        ]
        
        let attributesToUpdate: [String: Any] = [
            kSecAttrIsInvisible as String: true,
            kSecValueData as String: pinData
        ]
        
        status = SecItemUpdate(updateQuery as CFDictionary, attributesToUpdate as CFDictionary)
    }
}

public func retrieveCachedPIN(for instanceID: String) throws -> String? {
    // Create LAContext for authentication
    let context = LAContext()
    context.localizedReason = "unlock your PIN"
    context.localizedCancelTitle = "Cancel"
    
    // Optional: Customize the authentication UI
    #if os(iOS)
    context.localizedFallbackTitle = "Use Passcode"
    #endif
    
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: getKeychainID(forInstanceID: instanceID),
        kSecAttrService as String: "SmartCardPIN",
        kSecReturnData as String: true,
        kSecUseDataProtectionKeychain as String: true,
        kSecUseAuthenticationContext as String: context,
        kSecAttrIsInvisible as String: true,
    ]
    
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    
    guard status == errSecSuccess,
          let pinData = result as? Data,
          let pin = String(data: pinData, encoding: .utf8) else {
        throw TKError(.authenticationNeeded)
    }
    
    return pin
}

func deleteCachedPIN(for instanceID: String) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: getKeychainID(forInstanceID: instanceID),
        kSecAttrService as String: "SmartCardPIN",
        kSecUseDataProtectionKeychain as String: true
    ]
    
    let status = SecItemDelete(query as CFDictionary)
    
    // Success or item not found are both acceptable
    guard status == errSecSuccess || status == errSecItemNotFound else {
        throw TKError(.corruptedData)
    }
}
