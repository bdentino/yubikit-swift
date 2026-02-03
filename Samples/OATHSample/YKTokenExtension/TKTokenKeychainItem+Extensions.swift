//
//  TKTokenKeychainItem+Extensions.swift
//  OATHSample
//
//  Created by Brian Dentino on 2/1/26.
//

import Foundation
import CryptoTokenKit
import X509
import SwiftASN1
import YubiKit
import OSLog

private let smartCardLogonOID = "1.3.6.1.4.1.311.20.2.2"

extension TKTokenKeychainKey {
    func applyKeyUsage(fromCertificate certificate: Certificate, forSlot slot: PIV.Slot, withMetadata metadata: PIV.SlotMetadata) {
        self.applyUsageIndicators(fromCertificate: certificate)
        self.applySlotUsageRestrictions(forSlot: slot, withMetadata: metadata)
    }
    
    func isSupportedByYubiKeyVersion(_ version: YubiKit.Version) -> Bool {
        let keyType = self.keyType as CFString
        let keySize = self.keySizeInBits
        os_log(.debug, log: log, "Checking yubikey version support for %{public}d bit %{public}@ key", keySize, keyType as String)
        switch keyType {
        case kSecAttrKeyTypeRSA:
            if keySize == 3072 || keySize == 4096 {
                return PIVSessionFeature.rsa3072and4096.isSupported(by: version)
            }
            return keySize <= 2048

        case kSecAttrKeyTypeECSECPrimeRandom:
            switch keySize {
            case 256:
                return true
            case 384:
                return PIVSessionFeature.p384.isSupported(by: version)
            default:
                return false
            }

        default:
            return true
        }
    }
    
    fileprivate func applyUsageIndicators(fromCertificate certificate: Certificate) {
        var canSign = self.canSign
        var canDecrypt = self.canDecrypt
        var canPerformKeyExchange = self.canPerformKeyExchange
        var isSuitableForLogin = self.isSuitableForLogin
        
        // Set key capabilities based on the actual usage indicated in the certificate.
        // This lets us use retired keyslots for more than just decryption (which is
        // how the default system PIV extension exposes them), enabling use cases such
        // as putting multiple different signing identities on a single card.
        if let keyUsage = try? certificate.extensions.keyUsage {
            canSign = false
            canDecrypt = false
            canPerformKeyExchange = false
            
            if keyUsage.digitalSignature || keyUsage.nonRepudiation {
                canSign = true
            }
            if keyUsage.keyEncipherment || keyUsage.dataEncipherment {
                canDecrypt = true
            }
            if keyUsage.keyAgreement {
                canPerformKeyExchange = true
            }
            if keyUsage.keyCertSign || keyUsage.cRLSign {
                canSign = true
            }
        }
        
        if let extendedKeyUsage = try? certificate.extensions.extendedKeyUsage {
            for usage in extendedKeyUsage {
                if usage == .any {
                    canSign = true
                    canDecrypt = true
                    canPerformKeyExchange = true
                    break
                }
                if usage == .serverAuth || usage == .clientAuth {
                    isSuitableForLogin = true
                }
                if usage == .codeSigning || usage == .timeStamping || usage == .ocspSigning {
                    canSign = true
                }
                if usage == .emailProtection {
                    canSign = true
                    canDecrypt = true
                }
                if usage.description == smartCardLogonOID {
                    isSuitableForLogin = true
                }
            }
        }
        
        self.canSign = canSign
        self.canDecrypt = canDecrypt
        self.canPerformKeyExchange = canPerformKeyExchange
        self.isSuitableForLogin = isSuitableForLogin
    }
    
    fileprivate func applySlotUsageRestrictions(forSlot slot: PIV.Slot, withMetadata metadata: PIV.SlotMetadata) {
        // Apply appropriate restrictions to certificates in standard PIV slots
        // so that the system doesn't unexpectedly try to use a certificate for
        // a purpose it wasn't intended for, regardless of whether or not the
        // certificate in that slot supports such operations.
        if slot == .authentication {
            self.canDecrypt = false
            self.canPerformKeyExchange = false
        }
        if slot == .signature {
            self.canDecrypt = false
            self.canPerformKeyExchange = false
            self.isSuitableForLogin = false
        }
        if slot == .keyManagement {
            self.canSign = false
            self.isSuitableForLogin = false
        }
        if slot == .cardAuth {
            self.canDecrypt = false
            self.canPerformKeyExchange = false
            self.isSuitableForLogin = false
        }
        if slot == .attestation {
            self.canSign = false
            self.canDecrypt = false
            self.canPerformKeyExchange = false
            self.isSuitableForLogin = false
        }
        
        var constraints: [ NSNumber: Any ] = [:]
        
        let pinPolicy = metadata.pinPolicy
        if self.canSign {
            applyPinPolicy(pinPolicy, forOperation: .signData, inSlot: slot, toConstraints: &constraints)
        }
        if self.canDecrypt {
            applyPinPolicy(pinPolicy, forOperation: .decryptData, inSlot: slot, toConstraints: &constraints)
        }
        if self.canPerformKeyExchange {
            applyPinPolicy(pinPolicy, forOperation: .performKeyExchange, inSlot: slot, toConstraints: &constraints)
        }
        
        self.constraints = constraints
    }
}

func applyPinPolicy(
    _ pinPolicy: PIV.PinPolicy,
    forOperation operation: TKTokenOperation,
    inSlot slot: PIV.Slot,
    toConstraints constraints: inout [NSNumber : Any]) {
    switch pinPolicy {
    case .never:
        constraints.updateValue(true, forKey: NSNumber(value: operation.rawValue))
    case .once, .always, .matchOnce, .matchAlways:
        constraints.updateValue("PIN", forKey: NSNumber(value: operation.rawValue))
    case .defaultPolicy:
        switch slot {
        case .cardAuth:
            constraints.updateValue(true, forKey: NSNumber(value: operation.rawValue))
        default:
            constraints.updateValue("PIN", forKey: NSNumber(value: operation.rawValue))
        }
    }
}
