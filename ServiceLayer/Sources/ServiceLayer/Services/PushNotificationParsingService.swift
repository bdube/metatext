// Copyright © 2021 Metabolist. All rights reserved.

import Combine
import CryptoKit
import DB
import Foundation
import Mastodon
import MastodonAPI
import Secrets

enum NotificationExtensionServiceError: Error {
    case userInfoDataAbsent
    case keychainDataAbsent
    case encryptedMessageTooShort
    case invalidRecordSize
    case invalidPadding
}

public struct PushNotificationParsingService {
    private let environment: AppEnvironment

    public init(environment: AppEnvironment) {
        self.environment = environment
    }
}

public extension PushNotificationParsingService {
    /// Identity passed as a param when registering the Web Push subscription URL.
    /// Defined by `feditext-apns`.
    static let identityIdUserInfoKey = "i"
    static let pushNotificationUserInfoKey = "com.metabolist.metatext.push-notification-user-info-key"

    func extractAndDecrypt(userInfo: [AnyHashable: Any]) throws -> (Data, Identity.Id) {
        guard let identityIdString = userInfo[Self.identityIdUserInfoKey] as? String,
              let identityId = Identity.Id(uuidString: identityIdString),
              let encryptedMessageBase64 = (userInfo[Self.encryptedMessageUserInfoKey] as? String)?
                .urlSafeBase64ToBase64(),
              let encryptedMessage = Data(base64Encoded: encryptedMessageBase64),
              let contentEncodingString = userInfo[Self.contentEncodingUserInfoKey] as? String,
              let contentEncoding = ContentEncoding(rawValue: contentEncodingString)
        else { throw NotificationExtensionServiceError.userInfoDataAbsent }
      
        let saltBase64 = (userInfo[Self.saltUserInfoKey] as? String)?
            .urlSafeBase64ToBase64()
        let salt = saltBase64.flatMap { Data(base64Encoded: $0) }
      
        let serverPublicKeyBase64 = (userInfo[Self.serverPublicKeyUserInfoKey] as? String)?
            .urlSafeBase64ToBase64()
        let serverPublicKeyData = serverPublicKeyBase64.flatMap { Data(base64Encoded: $0) }
          
        let secrets = Secrets(identityId: identityId, keychain: environment.keychain)

        guard let auth = try secrets.getPushAuth(),
              let pushKey = try secrets.getPushKey()
        else { throw NotificationExtensionServiceError.keychainDataAbsent }

        return (
            try Self.decrypt(
                contentEncoding: contentEncoding,
                encryptedMessage: encryptedMessage,
                privateKeyData: pushKey,
                serverPublicKeyData: serverPublicKeyData,
                auth: auth,
                salt: salt
            ),
            identityId
        )
    }

    func handle(identityId: Identity.Id) -> Result<String, Error> {
        let secrets = Secrets(identityId: identityId, keychain: environment.keychain)

        return Result { try secrets.getUsername().appending("@").appending(secrets.getInstanceURL().host ?? "") }
    }

    func title(pushNotification: PushNotification, identityId: Identity.Id) -> AnyPublisher<String, Error> {
        switch pushNotification.notificationType {
        case .poll, .status:
            let secrets = Secrets(identityId: identityId, keychain: environment.keychain)
            let instanceURL: URL
            let mastodonAPIClient: MastodonAPIClient

            do {
                instanceURL = try secrets.getInstanceURL()
                mastodonAPIClient = try MastodonAPIClient(
                    session: .shared,
                    instanceURL: instanceURL,
                    apiCapabilities: secrets.getAPICapabilities(),
                    accessToken: pushNotification.accessToken
                )
            } catch {
                return Fail(error: error).eraseToAnyPublisher()
            }

            let endpoint = NotificationEndpoint.notification(id: pushNotification.notificationId)

            return mastodonAPIClient.request(endpoint)
                .map {
                    switch pushNotification.notificationType {
                    case .status:
                        return String.localizedStringWithFormat(
                            NSLocalizedString("notification.status-%@", comment: ""),
                            $0.account.displayName)
                    case .poll:
                        guard let accountId = try? secrets.getAccountId() else {
                            return NSLocalizedString("notification.poll.unknown", comment: "")
                        }

                        if $0.account.id == accountId {
                            return NSLocalizedString("notification.poll.own", comment: "")
                        } else {
                            return NSLocalizedString("notification.poll", comment: "")
                        }
                    default:
                        return pushNotification.title
                    }
                }
                .eraseToAnyPublisher()
        default:
            return Just(pushNotification.title).setFailureType(to: Error.self).eraseToAnyPublisher()
        }
    }
}

internal extension PushNotificationParsingService {
    /// `Content-Encoding` header.
    /// Defined by `feditext-apns`.
    static let contentEncodingUserInfoKey = "e"
    /// URL-safe Base64-encoded notification body.
    /// Defined by `feditext-apns`.
    static let encryptedMessageUserInfoKey = "m"
    /// Salt from `Encryption` header.
    /// Not used by `aes128gcm`-encoded notifications.
    /// Defined by `feditext-apns`.
    static let saltUserInfoKey = "s"
    /// Server's ECDH public key from `Crypto-Key` header.
    /// Not used by `aes128gcm`-encoded notifications.
    /// Defined by `feditext-apns`.
    static let serverPublicKeyUserInfoKey = "k"
    
    enum ContentEncoding: String {
        case aesgcm
        case aes128gcm
    }
  
    static let keyLength = 16
    static let nonceLength = 12
    static let pseudoRandomKeyLength = 32
    static let paddedByteCount = 2
    static let curve = "P-256"

    /// Shared info constants for some HKDF operations.
    enum HKDFInfo: String {
        case auth, aesgcm, nonce, aes128gcm, webpush

        var bytes: [UInt8] {
            switch self {
            case .webpush:
                Array("WebPush: info\0".utf8)
            default:
                Array("Content-Encoding: \(self)\0".utf8)
            }
        }
    }

    /// Decrypt a Web Push notification that might be the draft or final encrypted format.
    /// If it's the draft format, `feditext-apns` includes values from the additional headers.
    static func decrypt(
        contentEncoding: ContentEncoding,
        encryptedMessage: Data,
        privateKeyData: Data,
        serverPublicKeyData: Data?,
        auth: Data,
        salt: Data?
    ) throws -> Data {
        switch contentEncoding {
        case .aesgcm:
            guard let salt, let serverPublicKeyData else {
                throw NotificationExtensionServiceError.userInfoDataAbsent
            }
            return try decryptAESGCM(
                encryptedMessage: encryptedMessage,
                privateKeyData: privateKeyData,
                serverPublicKeyData: serverPublicKeyData,
                auth: auth,
                salt: salt
            )

        case .aes128gcm:
            return try decryptAES128GCM(
                encryptedMessageWithHeader: encryptedMessage,
                privateKeyData: privateKeyData,
                auth: auth
            )
        }
    }
  
    /// Decrypt draft RFC 8291 format.
    static func decryptAESGCM(
        encryptedMessage: Data,
        privateKeyData: Data,
        serverPublicKeyData: Data,
        auth: Data,
        salt: Data
    ) throws -> Data {
        let privateKey = try P256.KeyAgreement.PrivateKey(x963Representation: privateKeyData)
        let serverPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: serverPublicKeyData)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)

        var keyInfo = HKDFInfo.aesgcm.bytes
        var nonceInfo = HKDFInfo.nonce.bytes
        var context = Array(curve.utf8)
        let publicKeyData = privateKey.publicKey.x963Representation

        context.append(0)
        context.append(0)
        context.append(UInt8(publicKeyData.count))
        context += Array(publicKeyData)
        context.append(0)
        context.append(UInt8(serverPublicKeyData.count))
        context += Array(serverPublicKeyData)

        keyInfo += context
        nonceInfo += context

        let pseudoRandomKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: auth,
            sharedInfo: HKDFInfo.auth.bytes,
            outputByteCount: pseudoRandomKeyLength)
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: pseudoRandomKey,
            salt: salt,
            info: keyInfo,
            outputByteCount: keyLength)
        let nonce = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: pseudoRandomKey,
            salt: salt,
            info: nonceInfo,
            outputByteCount: nonceLength)

        let sealedBox = try AES.GCM.SealedBox(combined: nonce.withUnsafeBytes(Array.init) + encryptedMessage)
        let decrypted = try AES.GCM.open(sealedBox, using: key)
        let unpadded = decrypted.suffix(from: paddedByteCount)

        return Data(unpadded)
    }
    
    static let headerSaltStart = 0
    static let headerSaltEnd = 16 + headerSaltStart
    static let headerRecordSizeStart = headerSaltEnd
    static let headerRecordSizeEnd = 4 + headerRecordSizeStart
    static let headerKeyIDLengthStart = headerRecordSizeEnd
    static let headerKeyIDLengthEnd = 1 + headerKeyIDLengthStart
    static let headerKeyIDStart = headerKeyIDLengthEnd
  
    /// RFC 8291 doesn't allow the multi-record option of RFC 8188,
    /// so there's only ever one record and the padding delimiter is always the same.
    static let lastRecordPaddingDelimiter = 2

    /// Decrypt final RFC 8291/RFC 8188 format.
    static func decryptAES128GCM(
        encryptedMessageWithHeader: Data,
        privateKeyData: Data,
        auth: Data
    ) throws -> Data {
        guard encryptedMessageWithHeader.count > headerKeyIDLengthEnd else {
            throw NotificationExtensionServiceError.encryptedMessageTooShort
        }
        
        let salt = encryptedMessageWithHeader[headerSaltStart..<headerSaltEnd]

        let recordSize: UInt32 = encryptedMessageWithHeader[headerRecordSizeStart..<headerRecordSizeEnd]
            .withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard recordSize >= 18 else {
            throw NotificationExtensionServiceError.invalidRecordSize
        }

        let keyIDLength: UInt8 = encryptedMessageWithHeader[headerKeyIDLengthStart]
        let headerKeyIDEnd = Int(keyIDLength) + headerKeyIDStart
        // RFC 8291 uses the RFC 8188 key ID header field as the actual key.
        let serverPublicKeyData = encryptedMessageWithHeader[headerKeyIDStart..<headerKeyIDEnd]
      
        guard encryptedMessageWithHeader.count > headerKeyIDEnd else {
            throw NotificationExtensionServiceError.encryptedMessageTooShort
        }
        let encryptedMessage = encryptedMessageWithHeader[headerKeyIDEnd...]
      
        let privateKey = try P256.KeyAgreement.PrivateKey(x963Representation: privateKeyData)
        let serverPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: serverPublicKeyData)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
      
        // Input key material for content encryption key derivation.
        let keyInfo = HKDFInfo.webpush.bytes
            + privateKey.publicKey.x963Representation
            + serverPublicKey.x963Representation
        let inputKeyMaterial = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: auth,
            sharedInfo: keyInfo,
            outputByteCount: pseudoRandomKeyLength
        )

        // Content encryption key.
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: HKDFInfo.aes128gcm.bytes,
            outputByteCount: keyLength
        )
      
        let nonce = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: HKDFInfo.nonce.bytes,
            outputByteCount: nonceLength
        )
        
        let sealedBox = try AES.GCM.SealedBox(
            combined: nonce.withUnsafeBytes(Array.init) + encryptedMessage
        )
        let decrypted = try AES.GCM.open(sealedBox, using: key)
        
        // Remove trailing padding.
        var byteIndex = decrypted.count - 1
        while byteIndex >= 0 && decrypted[byteIndex] == 0 {
            byteIndex -= 1
        }
        guard
            byteIndex >= 0,
            decrypted[byteIndex] == lastRecordPaddingDelimiter
        else {
            throw NotificationExtensionServiceError.invalidPadding
        }
        let unpadded = decrypted.prefix(byteIndex)
        
        return Data(unpadded)
    }
}
