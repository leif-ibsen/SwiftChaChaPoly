//
//  Test2.swift
//  
//
//  Created by Leif Ibsen on 12/09/2023.
//

import XCTest
@testable import SwiftChaChaPoly

// Test vectors from project Wycheproof - chacha20_poly1305_test.json
final class TestWycheproof: XCTestCase {

    static func hex2bytes(_ x: String) -> Bytes {
        let b = [Byte](x.utf8)
        var bytes = Bytes(repeating: 0, count: b.count / 2)
        for i in 0 ..< bytes.count {
            let b0 = b[2 * i]
            let b1 = b[2 * i + 1]
            bytes[i] = ((b0 > 57 ? b0 - 97 + 10 : b0 - 48) << 4) | (b1 > 57 ? b1 - 97 + 10 : b1 - 48)
        }
        return bytes
    }

    struct chaChaPolyTest {

        let key: Bytes
        let iv: Bytes
        let aad: Bytes
        let msg: Bytes
        let ct: Bytes
        let tag: Bytes

        init(_ key: String, _ iv: String, _ aad: String, _ msg: String, _ ct: String, _ tag: String) {
            self.key = hex2bytes(key)
            self.iv = hex2bytes(iv)
            self.aad = hex2bytes(aad)
            self.msg = hex2bytes(msg)
            self.ct = hex2bytes(ct)
            self.tag = hex2bytes(tag)
        }
    }

    let okTests: [chaChaPolyTest] = [
        // tcId = 2
        chaChaPolyTest(
            "80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0",
            "4da5bf8dfd5852c1ea12379d",
            "",
            "",
            "",
            "76acb342cf3166a5b63c0c0ea1383c8d"),
        // tcId = 3
        chaChaPolyTest(
            "7a4cd759172e02eb204db2c3f5c746227df584fc1345196391dbb9577a250742",
            "a92ef0ac991dd516a3c6f689",
            "bd506764f2d2c410",
            "",
            "",
            "906fa6284b52f87b7359cbaa7563c709"),
        // tcId = 122
        chaChaPolyTest(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "000102030405060708090a0b",
            "00000000000000000000000000000000",
            "65b63bf074b7283992e24b1ac0df0d22b555dbe2254d94a43f1de748d3cc6f0d",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "39f4fce3026d83789ffd1ee6f2cd7c4f"),
        // tcId = 125
        chaChaPolyTest(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "000102030405060708090a0b",
            "ffffffffffffffffffffffffffffffff",
            "9a49c40f8b48d7c66d1db4e53f20f2dd4aaa241ddab26b5bc0e218b72c3390f2",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "37e3399d9ca696799f08f4f72bc0cdd8"),
        // tcId = 206
        chaChaPolyTest(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060710abb165",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "dc8ce708bf26aab862d97e1b42f31ef38c382cf07174142ea564920612997b1c2e38aca2438b588d5459493e97e7fa330ff9bc3b9458297ba0967d86ed090b435103478f2869b93ee29c837e95fb6b9903f3b735b7345428eb93b3db1d9b5187cebb889aa177d83e4f63fc9a5c0596eed939883d06aacdfdea44fdecdf5cb7fc",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "c296436246c3a7c4b3ba09ab2a6a0889"),
        // tcId = 226
        chaChaPolyTest(
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            "000102030405060708090a0b",
            "ffffffffffffffffffffffffffffffff415771fda4fbcc55c377f73203e60226",
            "e48caf8a76183327c9561a4651c07c822ccd1642c06607d0d4bc0afb4de15915dbfa3b0b422e77e15c64bf6247031f15fdb643117809821870000adf83834da5",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "000102030405060708090a0b0c0d0e0f"),
        // tcId = 227
        chaChaPolyTest(
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            "000102030405060708090a0b",
            "f1ffffffffffffffffffffffffffffff615af39eddb5fcd2519190d5507d3b06",
            "e48caf8a76183327c9561a4651c07c822ccd1642c06607d0d4bc0afb4de15915dbfa3b0b422e77e15c64bf6247031f15fdb643117809821870000adf83834da5",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "00000000000000000000000000000000"),
        // tcId = 228
        chaChaPolyTest(
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            "000102030405060708090a0b",
            "b5ffffffffffffffffffffffffffffff764e5d82ce7da0d44148484fd96a6107",
            "e48caf8a76183327c9561a4651c07c822ccd1642c06607d0d4bc0afb4de15915dbfa3b0b422e77e15c64bf6247031f15fdb643117809821870000adf83834da5",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff"),
        // tcId = 316
        chaChaPolyTest(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060703e76f6f",
            "ffffffff",
            "1fde9b9ec8b247d42bbee2016d6715ba66d624f288f52941ca24865ce96f0d9736ff33a27c23f4976fc74f1fcd82f5cca0ef17caee342362a78c15031335a8a3",
            "ffffffffffffffffffffffffffffffffdba35e4e633a3c646379bc7f82db98ce07f07c0b2132c73943308806721c542707f07c0b2132c73943308806721c5427",
            "38bfb8318c627d86c34bab1f1ebd0db0"),
    ]

    let failTests: [chaChaPolyTest] = [
        // tcId = 146
        chaChaPolyTest(
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "000102030405060708090a0b",
            "000102",
            "",
            "",
            "f5409bb729039d0814ac514054323f44"),
        // tcId = 162
        chaChaPolyTest(
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "000102030405060708090a0b",
            "000102",
            "",
            "",
            "f4409bb729039d0814ac514054323fc4"),
    ]

    func testOk() throws {
        for t in okTests {
            let chaChaPoly = try ChaChaPoly(t.key, t.iv)
            var ct = t.msg
            let tag = chaChaPoly.encrypt(&ct, t.aad)
            XCTAssertEqual(tag, t.tag)
            let ok = chaChaPoly.decrypt(&ct, t.tag, t.aad)
            XCTAssertTrue(ok)
            XCTAssertEqual(ct, t.msg)
        }
    }

    func testFail() throws {
        for t in failTests {
            let chaChaPoly = try ChaChaPoly(t.key, t.iv)
            var ct = t.msg
            let tag = chaChaPoly.encrypt(&ct, t.aad)
            XCTAssertNotEqual(tag, t.tag)
            let ok = chaChaPoly.decrypt(&ct, t.tag, t.aad)
            XCTAssertFalse(ok)
            XCTAssertEqual(ct, t.msg)
        }
    }

    func testException() throws {
        do {
            let _ = try ChaChaPoly(Bytes(repeating: 1, count: 10), Bytes(repeating: 1, count: 12))
            XCTFail("Expected Ex.keySize exception")
        } catch ChaChaPoly.Ex.keySize {
        } catch {
            XCTFail("Expected Ex.keySize exception")
        }
        do {
            let _ = try ChaChaPoly(Bytes(repeating: 1, count: 32), Bytes(repeating: 1, count: 10))
            XCTFail("Expected Ex.nonceSize exception")
        } catch ChaChaPoly.Ex.nonceSize {
        } catch {
            XCTFail("Expected Ex.nonceSize exception")
        }
    }

}
