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

import CryptoTokenKit
import CommonCrypto
import YubiKit

private let rsaKeyType = kSecAttrKeyTypeRSA as String
private let ecPrimeKeyType = kSecAttrKeyTypeECSECPrimeRandom as String

private let baseYubiKeyAlgorithms: Set<SecKeyAlgorithm> = [
    // RSA PKCS#1 v1.5 signing (message + digest)
    .rsaSignatureMessagePKCS1v15SHA1,
    .rsaSignatureMessagePKCS1v15SHA224,
    .rsaSignatureMessagePKCS1v15SHA256,
    .rsaSignatureMessagePKCS1v15SHA384,
    .rsaSignatureMessagePKCS1v15SHA512,
    .rsaSignatureDigestPKCS1v15SHA1,
    .rsaSignatureDigestPKCS1v15SHA224,
    .rsaSignatureDigestPKCS1v15SHA256,
    .rsaSignatureDigestPKCS1v15SHA384,
    .rsaSignatureDigestPKCS1v15SHA512,

    // RSA decrypt / unwrap
    .rsaEncryptionRaw,
    .rsaEncryptionPKCS1,
    .rsaEncryptionOAEPSHA1,
    .rsaEncryptionOAEPSHA224,
    .rsaEncryptionOAEPSHA256,
    .rsaEncryptionOAEPSHA384,
    .rsaEncryptionOAEPSHA512,

    // ECDSA signing (P‑256 / P‑384)
    .ecdsaSignatureMessageX962SHA1,
    .ecdsaSignatureMessageX962SHA224,
    .ecdsaSignatureMessageX962SHA256,
    .ecdsaSignatureMessageX962SHA384,
    .ecdsaSignatureMessageX962SHA512,
    .ecdsaSignatureDigestX962SHA1,
    .ecdsaSignatureDigestX962SHA224,
    .ecdsaSignatureDigestX962SHA256,
    .ecdsaSignatureDigestX962SHA384,
    .ecdsaSignatureDigestX962SHA512,

    // ECDH (standard + cofactor)
    .ecdhKeyExchangeStandard,
    .ecdhKeyExchangeCofactor
]

private let featureRequirements: [PIVSessionFeature: Set<SecKeyAlgorithm>] = [
    .p384: [
        .ecdsaSignatureMessageX962SHA384,
        .ecdsaSignatureMessageX962SHA512,
        .ecdsaSignatureDigestX962SHA384,
        .ecdsaSignatureDigestX962SHA512,
        .ecdhKeyExchangeStandardX963SHA384,
        .ecdhKeyExchangeStandardX963SHA512,
        .ecdhKeyExchangeCofactorX963SHA384,
        .ecdhKeyExchangeCofactorX963SHA512
    ],
    .ed25519: [],
    .x25519: []
]

private let softwareSupportedAlgorithms: [SecKeyAlgorithm: Set<SecKeyAlgorithm>] = [
    .rsaEncryptionOAEPSHA1AESGCM: [.rsaEncryptionOAEPSHA1],
    .rsaEncryptionOAEPSHA224AESGCM: [.rsaEncryptionOAEPSHA224],
    .rsaEncryptionOAEPSHA256AESGCM: [.rsaEncryptionOAEPSHA256],
    .rsaEncryptionOAEPSHA384AESGCM: [.rsaEncryptionOAEPSHA384],
    .rsaEncryptionOAEPSHA512AESGCM: [.rsaEncryptionOAEPSHA512],
    .ecdhKeyExchangeStandardX963SHA1: [.ecdhKeyExchangeStandard],
    .ecdhKeyExchangeStandardX963SHA224: [.ecdhKeyExchangeStandard],
    .ecdhKeyExchangeStandardX963SHA256: [.ecdhKeyExchangeStandard],
    .ecdhKeyExchangeStandardX963SHA384: [.ecdhKeyExchangeStandard],
    .ecdhKeyExchangeStandardX963SHA512: [.ecdhKeyExchangeStandard],
    .ecdhKeyExchangeCofactorX963SHA1: [.ecdhKeyExchangeCofactor],
    .ecdhKeyExchangeCofactorX963SHA224: [.ecdhKeyExchangeCofactor],
    .ecdhKeyExchangeCofactorX963SHA256: [.ecdhKeyExchangeCofactor],
    .ecdhKeyExchangeCofactorX963SHA384: [.ecdhKeyExchangeCofactor],
    .ecdhKeyExchangeCofactorX963SHA512: [.ecdhKeyExchangeCofactor]
]

extension TKTokenKeyAlgorithm {
    func isSupportedByYubiKey(version: Version?) -> Bool {
        let secKeyAlgo = self.secKeyAlgorithm
        guard let secKeyAlgo else { return false }
        guard baseYubiKeyAlgorithms.contains(secKeyAlgo) || self.isSupportedByExtension() else { return false }
        
        guard let version else { return true }
        for (feature, algorithms) in featureRequirements where algorithms.contains(secKeyAlgo) {
            if !feature.isSupported(by: version) {
                return false
            }
        }
        
        return true
    }
    
    func isSupportedByExtension() -> Bool {
        let secKeyAlgo = self.secKeyAlgorithm
        guard let secKeyAlgo else { return false }
        if baseYubiKeyAlgorithms.contains(secKeyAlgo) {
            return true
        }
        
        guard let baseAlgorithms = softwareSupportedAlgorithms[secKeyAlgo] else {
            return false
        }
        
        for algorithm in baseAlgorithms {
            if !baseYubiKeyAlgorithms.contains(algorithm) {
                return false
            }
        }
        
        return true
    }
    
    var secKeyAlgorithm: SecKeyAlgorithm? {
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureRaw) {
            return SecKeyAlgorithm.rsaSignatureRaw
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureDigestPKCS1v15Raw) {
            return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15Raw
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA1) {
            return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA1
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA224) {
            return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA224
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256) {
            return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA384) {
            return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA384
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA512) {
            return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA512
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA1) {
            return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA1
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA224) {
            return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA224
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256) {
            return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA384) {
            return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA384
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512) {
            return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureDigestPSSSHA1) {
            return SecKeyAlgorithm.rsaSignatureDigestPSSSHA1
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureDigestPSSSHA224) {
            return SecKeyAlgorithm.rsaSignatureDigestPSSSHA224
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureDigestPSSSHA256) {
            return SecKeyAlgorithm.rsaSignatureDigestPSSSHA256
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureDigestPSSSHA384) {
            return SecKeyAlgorithm.rsaSignatureDigestPSSSHA384
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureDigestPSSSHA512) {
            return SecKeyAlgorithm.rsaSignatureDigestPSSSHA512
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureMessagePSSSHA1) {
            return SecKeyAlgorithm.rsaSignatureMessagePSSSHA1
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureMessagePSSSHA224) {
            return SecKeyAlgorithm.rsaSignatureMessagePSSSHA224
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureMessagePSSSHA256) {
            return SecKeyAlgorithm.rsaSignatureMessagePSSSHA256
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureMessagePSSSHA384) {
            return SecKeyAlgorithm.rsaSignatureMessagePSSSHA384
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaSignatureMessagePSSSHA512) {
            return SecKeyAlgorithm.rsaSignatureMessagePSSSHA512
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureDigestRFC4754) {
            return SecKeyAlgorithm.ecdsaSignatureDigestRFC4754
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureDigestX962) {
            return SecKeyAlgorithm.ecdsaSignatureDigestX962
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureDigestX962SHA1) {
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA1
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureDigestX962SHA224) {
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA224
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256) {
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureDigestX962SHA384) {
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA384
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureDigestX962SHA512) {
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA512
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureMessageX962SHA1) {
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA1
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureMessageX962SHA224) {
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA224
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256) {
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384) {
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512) {
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionRaw) {
            return SecKeyAlgorithm.rsaEncryptionRaw
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionPKCS1) {
            return SecKeyAlgorithm.rsaEncryptionPKCS1
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionOAEPSHA1) {
            return SecKeyAlgorithm.rsaEncryptionOAEPSHA1
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionOAEPSHA224) {
            return SecKeyAlgorithm.rsaEncryptionOAEPSHA224
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionOAEPSHA256) {
            return SecKeyAlgorithm.rsaEncryptionOAEPSHA256
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionOAEPSHA384) {
            return SecKeyAlgorithm.rsaEncryptionOAEPSHA384
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionOAEPSHA512) {
            return SecKeyAlgorithm.rsaEncryptionOAEPSHA512
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionOAEPSHA1AESGCM) {
            return SecKeyAlgorithm.rsaEncryptionOAEPSHA1AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionOAEPSHA224AESGCM) {
            return SecKeyAlgorithm.rsaEncryptionOAEPSHA224AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionOAEPSHA256AESGCM) {
            return SecKeyAlgorithm.rsaEncryptionOAEPSHA256AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionOAEPSHA384AESGCM) {
            return SecKeyAlgorithm.rsaEncryptionOAEPSHA384AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.rsaEncryptionOAEPSHA512AESGCM) {
            return SecKeyAlgorithm.rsaEncryptionOAEPSHA512AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionStandardX963SHA1AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionStandardX963SHA1AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionStandardX963SHA224AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionStandardX963SHA224AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionStandardX963SHA384AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionStandardX963SHA384AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionStandardX963SHA512AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionStandardX963SHA512AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionCofactorX963SHA1AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionCofactorX963SHA1AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionCofactorX963SHA224AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionCofactorX963SHA224AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionCofactorX963SHA384AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionCofactorX963SHA384AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionCofactorX963SHA512AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionCofactorX963SHA512AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA224AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA224AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA256AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA256AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA384AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA384AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA512AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA512AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA224AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA224AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA384AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA384AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA512AESGCM) {
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA512AESGCM
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeStandard) {
            return SecKeyAlgorithm.ecdhKeyExchangeStandard
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA1) {
            return SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA1
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA224) {
            return SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA224
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256) {
            return SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA384) {
            return SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA384
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA512) {
            return SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA512
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeCofactor) {
            return SecKeyAlgorithm.ecdhKeyExchangeCofactor
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA1) {
            return SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA1
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA224) {
            return SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA224
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA256) {
            return SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA256
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA384) {
            return SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA384
        }
        if self.isAlgorithm(SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA512) {
            return SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA512
        }
        return nil
    }
    
    func supportsKeyType(_ keyType: String) -> Bool {
        guard let secAlgo = self.secKeyAlgorithm else { return false }
        
        switch keyType {
        case rsaKeyType:
            return isRSAAlgorithm(secAlgo)
        case ecPrimeKeyType:
            return isECAlgorithm(secAlgo)
        default:
            return false
        }
    }
}

public enum PIVAlgorithm: Sendable {
    case rsaSignature(PIV.RSASignatureAlgorithm)
    case rsaEncryption(PIV.RSAEncryptionAlgorithm)
    case rsaEncryptionOAEPAESGCM(hashAlgorithm: OAEPHashAlgorithm)
    case ecdsaSignature(PIV.ECDSASignatureAlgorithm)
    case ecdhKeyExchange(variant: ECDHVariant, kdf: ECDHKeyDerivation?)
        
    public enum OAEPHashAlgorithm: Sendable {
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
        
        var ccDigestAlgorithm: (_ data: Data) -> Data {
            return { data in
                var result = Data(count: self.digestLength)
                data.withUnsafeBytes { dataBytes in
                    result.withUnsafeMutableBytes { resultBytes in
                        guard let resultPtr = resultBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                            return
                        }
                        
                        switch self {
                        case .sha1:
                            CC_SHA1(dataBytes.baseAddress, CC_LONG(data.count), resultPtr)
                        case .sha224:
                            CC_SHA224(dataBytes.baseAddress, CC_LONG(data.count), resultPtr)
                        case .sha256:
                            CC_SHA256(dataBytes.baseAddress, CC_LONG(data.count), resultPtr)
                        case .sha384:
                            CC_SHA384(dataBytes.baseAddress, CC_LONG(data.count), resultPtr)
                        case .sha512:
                            CC_SHA512(dataBytes.baseAddress, CC_LONG(data.count), resultPtr)
                        }
                    }
                }
                return result
            }
        }
        
        var digestLength: Int {
            switch self {
            case .sha1: return Int(CC_SHA1_DIGEST_LENGTH)
            case .sha224: return Int(CC_SHA224_DIGEST_LENGTH)
            case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
            case .sha384: return Int(CC_SHA384_DIGEST_LENGTH)
            case .sha512: return Int(CC_SHA512_DIGEST_LENGTH)
            }
        }
        
        var oaepAlgorithm: PIV.RSAEncryptionAlgorithm {
            switch self {
            case .sha1: return .oaep(.sha1)
            case .sha224: return .oaep(.sha224)
            case .sha256: return .oaep(.sha256)
            case .sha384: return .oaep(.sha384)
            case .sha512: return .oaep(.sha512)
            }
        }
    }

    
    public enum ECDHVariant: Sendable {
        case standard
        case cofactor
    }
    
    public enum ECDHKeyDerivation: Sendable {
        case x963SHA1
        case x963SHA224
        case x963SHA256
        case x963SHA384
        case x963SHA512
        
        var digestLength: Int {
            switch self {
            case .x963SHA1: return Int(CC_SHA1_DIGEST_LENGTH)
            case .x963SHA224: return Int(CC_SHA224_DIGEST_LENGTH)
            case .x963SHA256: return Int(CC_SHA256_DIGEST_LENGTH)
            case .x963SHA384: return Int(CC_SHA384_DIGEST_LENGTH)
            case .x963SHA512: return Int(CC_SHA512_DIGEST_LENGTH)
            }
        }
        
        func hash(data: Data) -> Data {
            var result = Data(count: digestLength)
            data.withUnsafeBytes { dataBytes in
                result.withUnsafeMutableBytes { resultBytes in
                    guard let resultPtr = resultBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                        return
                    }
                    
                    switch self {
                    case .x963SHA1:
                        CC_SHA1(dataBytes.baseAddress, CC_LONG(data.count), resultPtr)
                    case .x963SHA224:
                        CC_SHA224(dataBytes.baseAddress, CC_LONG(data.count), resultPtr)
                    case .x963SHA256:
                        CC_SHA256(dataBytes.baseAddress, CC_LONG(data.count), resultPtr)
                    case .x963SHA384:
                        CC_SHA384(dataBytes.baseAddress, CC_LONG(data.count), resultPtr)
                    case .x963SHA512:
                        CC_SHA512(dataBytes.baseAddress, CC_LONG(data.count), resultPtr)
                    }
                }
            }
            return result
        }

    }

    
    /// Converts a SecKeyAlgorithm to the appropriate PIV algorithm
    public init?(secKeyAlgorithm: SecKeyAlgorithm) {
        // RSA Signature Algorithms - PKCS#1 v1.5
        switch secKeyAlgorithm {
        case .rsaSignatureDigestPKCS1v15SHA1:
            self = .rsaSignature(.pkcs1v15(.sha1))
        case .rsaSignatureDigestPKCS1v15SHA224:
            self = .rsaSignature(.pkcs1v15(.sha224))
        case .rsaSignatureDigestPKCS1v15SHA256:
            self = .rsaSignature(.pkcs1v15(.sha256))
        case .rsaSignatureDigestPKCS1v15SHA384:
            self = .rsaSignature(.pkcs1v15(.sha384))
        case .rsaSignatureDigestPKCS1v15SHA512:
            self = .rsaSignature(.pkcs1v15(.sha512))
        case .rsaSignatureDigestPKCS1v15Raw:
            self = .rsaSignature(.raw)
            
        // RSA Signature Algorithms - PSS
        case .rsaSignatureDigestPSSSHA1:
            self = .rsaSignature(.pss(.sha1))
        case .rsaSignatureDigestPSSSHA224:
            self = .rsaSignature(.pss(.sha224))
        case .rsaSignatureDigestPSSSHA256:
            self = .rsaSignature(.pss(.sha256))
        case .rsaSignatureDigestPSSSHA384:
            self = .rsaSignature(.pss(.sha384))
        case .rsaSignatureDigestPSSSHA512:
            self = .rsaSignature(.pss(.sha512))
            
        // RSA Message Signature Algorithms - PKCS#1 v1.5
        case .rsaSignatureMessagePKCS1v15SHA1:
            self = .rsaSignature(.pkcs1v15(.sha1))
        case .rsaSignatureMessagePKCS1v15SHA224:
            self = .rsaSignature(.pkcs1v15(.sha224))
        case .rsaSignatureMessagePKCS1v15SHA256:
            self = .rsaSignature(.pkcs1v15(.sha256))
        case .rsaSignatureMessagePKCS1v15SHA384:
            self = .rsaSignature(.pkcs1v15(.sha384))
        case .rsaSignatureMessagePKCS1v15SHA512:
            self = .rsaSignature(.pkcs1v15(.sha512))
            
        // RSA Message Signature Algorithms - PSS
        case .rsaSignatureMessagePSSSHA1:
            self = .rsaSignature(.pss(.sha1))
        case .rsaSignatureMessagePSSSHA224:
            self = .rsaSignature(.pss(.sha224))
        case .rsaSignatureMessagePSSSHA256:
            self = .rsaSignature(.pss(.sha256))
        case .rsaSignatureMessagePSSSHA384:
            self = .rsaSignature(.pss(.sha384))
        case .rsaSignatureMessagePSSSHA512:
            self = .rsaSignature(.pss(.sha512))
            
        // RSA Signature Raw
        case .rsaSignatureRaw:
            self = .rsaSignature(.raw)
            
        // RSA Encryption Algorithms
        case .rsaEncryptionPKCS1:
            self = .rsaEncryption(.pkcs1v15)
        case .rsaEncryptionOAEPSHA1:
            self = .rsaEncryption(.oaep(.sha1))
        case .rsaEncryptionOAEPSHA224:
            self = .rsaEncryption(.oaep(.sha224))
        case .rsaEncryptionOAEPSHA256:
            self = .rsaEncryption(.oaep(.sha256))
        case .rsaEncryptionOAEPSHA384:
            self = .rsaEncryption(.oaep(.sha384))
        case .rsaEncryptionOAEPSHA512:
            self = .rsaEncryption(.oaep(.sha512))
        case .rsaEncryptionRaw:
            self = .rsaEncryption(.raw)
            
        // RSA OAEP + AES-GCM hybrid encryption
        case .rsaEncryptionOAEPSHA1AESGCM:
            self = .rsaEncryptionOAEPAESGCM(hashAlgorithm: .sha1)
        case .rsaEncryptionOAEPSHA224AESGCM:
            self = .rsaEncryptionOAEPAESGCM(hashAlgorithm: .sha224)
        case .rsaEncryptionOAEPSHA256AESGCM:
            self = .rsaEncryptionOAEPAESGCM(hashAlgorithm: .sha256)
        case .rsaEncryptionOAEPSHA384AESGCM:
            self = .rsaEncryptionOAEPAESGCM(hashAlgorithm: .sha384)
        case .rsaEncryptionOAEPSHA512AESGCM:
            self = .rsaEncryptionOAEPAESGCM(hashAlgorithm: .sha512)
            
        // ECDSA Signature Algorithms - Digest (prehashed)
        case .ecdsaSignatureDigestX962SHA1:
            self = .ecdsaSignature(.prehashed(.sha1))
        case .ecdsaSignatureDigestX962SHA224:
            self = .ecdsaSignature(.prehashed(.sha224))
        case .ecdsaSignatureDigestX962SHA256:
            self = .ecdsaSignature(.prehashed(.sha256))
        case .ecdsaSignatureDigestX962SHA384:
            self = .ecdsaSignature(.prehashed(.sha384))
        case .ecdsaSignatureDigestX962SHA512:
            self = .ecdsaSignature(.prehashed(.sha512))
            
        // ECDSA Signature Algorithms - Message (hash internally)
        case .ecdsaSignatureMessageX962SHA1:
            self = .ecdsaSignature(.hash(.sha1))
        case .ecdsaSignatureMessageX962SHA224:
            self = .ecdsaSignature(.hash(.sha224))
        case .ecdsaSignatureMessageX962SHA256:
            self = .ecdsaSignature(.hash(.sha256))
        case .ecdsaSignatureMessageX962SHA384:
            self = .ecdsaSignature(.hash(.sha384))
        case .ecdsaSignatureMessageX962SHA512:
            self = .ecdsaSignature(.hash(.sha512))
            
        case .ecdhKeyExchangeStandard:
            self = .ecdhKeyExchange(variant: .standard, kdf: nil)
        case .ecdhKeyExchangeStandardX963SHA1:
            self = .ecdhKeyExchange(variant: .standard, kdf: .x963SHA1)
        case .ecdhKeyExchangeStandardX963SHA224:
            self = .ecdhKeyExchange(variant: .standard, kdf: .x963SHA224)
        case .ecdhKeyExchangeStandardX963SHA256:
            self = .ecdhKeyExchange(variant: .standard, kdf: .x963SHA256)
        case .ecdhKeyExchangeStandardX963SHA384:
            self = .ecdhKeyExchange(variant: .standard, kdf: .x963SHA384)
        case .ecdhKeyExchangeStandardX963SHA512:
            self = .ecdhKeyExchange(variant: .standard, kdf: .x963SHA512)
            
        case .ecdhKeyExchangeCofactor:
            self = .ecdhKeyExchange(variant: .cofactor, kdf: nil)
        case .ecdhKeyExchangeCofactorX963SHA1:
            self = .ecdhKeyExchange(variant: .cofactor, kdf: .x963SHA1)
        case .ecdhKeyExchangeCofactorX963SHA224:
            self = .ecdhKeyExchange(variant: .cofactor, kdf: .x963SHA224)
        case .ecdhKeyExchangeCofactorX963SHA256:
            self = .ecdhKeyExchange(variant: .cofactor, kdf: .x963SHA256)
        case .ecdhKeyExchangeCofactorX963SHA384:
            self = .ecdhKeyExchange(variant: .cofactor, kdf: .x963SHA384)
        case .ecdhKeyExchangeCofactorX963SHA512:
            self = .ecdhKeyExchange(variant: .cofactor, kdf: .x963SHA512)
            
        default:
            return nil
        }
    }
}

private func isRSAAlgorithm(_ algorithm: SecKeyAlgorithm) -> Bool {
    switch algorithm {
    // RSA Encryption
    case .rsaEncryptionRaw,
         .rsaEncryptionPKCS1,
         .rsaEncryptionOAEPSHA1,
         .rsaEncryptionOAEPSHA224,
         .rsaEncryptionOAEPSHA256,
         .rsaEncryptionOAEPSHA384,
         .rsaEncryptionOAEPSHA512,
         .rsaEncryptionOAEPSHA1AESGCM,
         .rsaEncryptionOAEPSHA224AESGCM,
         .rsaEncryptionOAEPSHA256AESGCM,
         .rsaEncryptionOAEPSHA384AESGCM,
         .rsaEncryptionOAEPSHA512AESGCM:
        return true
        
    // RSA Signature - Raw
    case .rsaSignatureRaw:
        return true
        
    // RSA Signature - PKCS1v15 Digest
    case .rsaSignatureDigestPKCS1v15Raw,
         .rsaSignatureDigestPKCS1v15SHA1,
         .rsaSignatureDigestPKCS1v15SHA224,
         .rsaSignatureDigestPKCS1v15SHA256,
         .rsaSignatureDigestPKCS1v15SHA384,
         .rsaSignatureDigestPKCS1v15SHA512:
        return true
        
    // RSA Signature - PKCS1v15 Message
    case .rsaSignatureMessagePKCS1v15SHA1,
         .rsaSignatureMessagePKCS1v15SHA224,
         .rsaSignatureMessagePKCS1v15SHA256,
         .rsaSignatureMessagePKCS1v15SHA384,
         .rsaSignatureMessagePKCS1v15SHA512:
        return true
        
    // RSA Signature - PSS Digest
    case .rsaSignatureDigestPSSSHA1,
         .rsaSignatureDigestPSSSHA224,
         .rsaSignatureDigestPSSSHA256,
         .rsaSignatureDigestPSSSHA384,
         .rsaSignatureDigestPSSSHA512:
        return true
        
    // RSA Signature - PSS Message
    case .rsaSignatureMessagePSSSHA1,
         .rsaSignatureMessagePSSSHA224,
         .rsaSignatureMessagePSSSHA256,
         .rsaSignatureMessagePSSSHA384,
         .rsaSignatureMessagePSSSHA512:
        return true
        
    default:
        return false
    }
}

private func isECAlgorithm(_ algorithm: SecKeyAlgorithm) -> Bool {
    switch algorithm {
    // ECDSA Signature - Digest
    case .ecdsaSignatureDigestX962,
         .ecdsaSignatureDigestX962SHA1,
         .ecdsaSignatureDigestX962SHA224,
         .ecdsaSignatureDigestX962SHA256,
         .ecdsaSignatureDigestX962SHA384,
         .ecdsaSignatureDigestX962SHA512:
        return true
        
    // ECDSA Signature - Message
    case .ecdsaSignatureMessageX962SHA1,
         .ecdsaSignatureMessageX962SHA224,
         .ecdsaSignatureMessageX962SHA256,
         .ecdsaSignatureMessageX962SHA384,
         .ecdsaSignatureMessageX962SHA512:
        return true
        
    // ECDH Key Exchange
    case .ecdhKeyExchangeStandard,
         .ecdhKeyExchangeCofactor,
         .ecdhKeyExchangeStandardX963SHA1,
         .ecdhKeyExchangeStandardX963SHA224,
         .ecdhKeyExchangeStandardX963SHA256,
         .ecdhKeyExchangeStandardX963SHA384,
         .ecdhKeyExchangeStandardX963SHA512,
         .ecdhKeyExchangeCofactorX963SHA1,
         .ecdhKeyExchangeCofactorX963SHA224,
         .ecdhKeyExchangeCofactorX963SHA256,
         .ecdhKeyExchangeCofactorX963SHA384,
         .ecdhKeyExchangeCofactorX963SHA512:
        return true
        
    // ECIES Encryption
    case .eciesEncryptionStandardX963SHA1AESGCM,
         .eciesEncryptionStandardX963SHA224AESGCM,
         .eciesEncryptionStandardX963SHA256AESGCM,
         .eciesEncryptionStandardX963SHA384AESGCM,
         .eciesEncryptionStandardX963SHA512AESGCM,
         .eciesEncryptionCofactorX963SHA1AESGCM,
         .eciesEncryptionCofactorX963SHA224AESGCM,
         .eciesEncryptionCofactorX963SHA256AESGCM,
         .eciesEncryptionCofactorX963SHA384AESGCM,
         .eciesEncryptionCofactorX963SHA512AESGCM:
        return true
        
    default:
        return false
    }
}
