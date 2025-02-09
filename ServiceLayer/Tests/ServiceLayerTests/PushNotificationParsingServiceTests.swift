// Copyright © 2025 Vyr Cossont. All rights reserved.

import CryptoKit
import Foundation
import XCTest

@testable import ServiceLayer

final class PushNotificationParsingServiceTests: XCTestCase {
  /// Decrypt example from https://datatracker.ietf.org/doc/html/rfc8291#section-5
  /// and https://datatracker.ietf.org/doc/html/rfc8291#appendix-A
  func testAES128GCM() throws {
    let encryptedMessage = Data(
        base64Encoded: """
            DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml\
            mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT\
            pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN
            """
            .urlSafeBase64ToBase64()
    )!

    // Note: user agent private key in RFC example is raw format,
    // but Feditext expects X9.63.
    let privateKeyData = try! P256.KeyAgreement.PrivateKey(
        rawRepresentation: Data(
            base64Encoded: "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
                .urlSafeBase64ToBase64()
        )!
    )
    .x963Representation

    let auth = Data(
        base64Encoded: "BTBZMqHH6r4Tts7J_aSIgg"
            .urlSafeBase64ToBase64()
    )!

    let decrypted = try PushNotificationParsingService.decryptAES128GCM(
        encryptedMessageWithHeader: encryptedMessage,
        privateKeyData: privateKeyData,
        auth: auth
    )

    guard let text = String(bytes: decrypted, encoding: .ascii) else {
        XCTFail("Couldn't decode decrypted message as ASCII!")
        return
    }

    XCTAssertEqual(text, "When I grow up, I want to be a watermelon")
  }
}
