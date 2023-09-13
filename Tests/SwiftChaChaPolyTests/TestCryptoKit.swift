//
//  Test3.swift
//  
//
//  Created by Leif Ibsen on 12/09/2023.
//

import XCTest
@testable import SwiftChaChaPoly
import CryptoKit

final class TestCryptoKit: XCTestCase {

    func randomBytes(_ bytes: inout Bytes) {
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
    }

    let msg = Bytes("Hi, there".utf8)
    let aad = Bytes("The AAD".utf8)
    
    func test1() throws {

        // CryptoKit seals, SwiftChaChaPoly decrypts

        let ckKey = CryptoKit.SymmetricKey(size: .bits256)
        let box = try CryptoKit.ChaChaPoly.seal(msg, using: ckKey, authenticating: aad)

        let key = ckKey.withUnsafeBytes {
            return Bytes($0)
        }
        let nonce = Bytes(box.nonce)
        let chacha = try ChaChaPoly(key, nonce)
        var ct = Bytes(box.ciphertext)
        let ok = chacha.decrypt(&ct, Bytes(box.tag), aad)
        XCTAssertTrue(ok)
        XCTAssertEqual(msg, ct)
    }

    func test2() throws {

        // SwiftChaChaPoly encrypts, CryptoKit opens

        var key = Bytes(repeating: 0, count: 32)
        randomBytes(&key)
        var nonce = Bytes(repeating: 0, count: 12)
        randomBytes(&nonce)
        let chacha = try ChaChaPoly(key, nonce)
        var ct = msg
        let tag = chacha.encrypt(&ct, aad)
        
        let ckKey = CryptoKit.SymmetricKey(data: key)
        let ckNonce = try CryptoKit.ChaChaPoly.Nonce(data: nonce)
        let box = try CryptoKit.ChaChaPoly.SealedBox(nonce: ckNonce, ciphertext: ct, tag: tag)
        let ct1 = try CryptoKit.ChaChaPoly.open(box, using: ckKey, authenticating: aad)
        XCTAssertEqual(msg, Bytes(ct1))
    }

}
