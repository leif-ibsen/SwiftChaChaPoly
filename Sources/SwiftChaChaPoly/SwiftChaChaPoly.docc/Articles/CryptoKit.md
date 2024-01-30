# CryptoKit Compatibility

## 

SwiftChaChaPoly is compatible with Apple's CryptoKit framework as the following examples show:

### Example 1: SwiftChaChaPoly encrypts, CryptoKit opens
```swift
import CryptoKit
import SwiftChaChaPoly

let msg = Bytes("Hi, there".utf8)
let aad = Bytes("The AAD".utf8)

let key = Bytes(repeating: 7, count: 32)
let nonce = Bytes(repeating: 1, count: 12)

let chacha = try ChaChaPoly(key, nonce)
var ct = msg
let tag = chacha.encrypt(&ct, aad)

// ct contains the ciphertext

let ckKey = CryptoKit.SymmetricKey(data: key)
let ckNonce = try CryptoKit.ChaChaPoly.Nonce(data: nonce)
let sealedBox = try CryptoKit.ChaChaPoly.SealedBox(nonce: ckNonce, ciphertext: ct, tag: tag)
let pt = try CryptoKit.ChaChaPoly.open(sealedBox, using: ckKey, authenticating: aad)
print(String(bytes: pt, encoding: .utf8)!)
```
giving:
```swift
Hi, there
```
### Example 2: CrypotoKit seals, SwiftChaChaPoly decrypts
```swift
import CryptoKit
import SwiftChaChaPoly

let msg = Bytes("Hi, there".utf8)
let aad = Bytes("The AAD".utf8)

let ckKey = CryptoKit.SymmetricKey(size: .bits256)
let sealedBox = try CryptoKit.ChaChaPoly.seal(msg, using: ckKey, authenticating: aad)

let key = ckKey.withUnsafeBytes {
    return Bytes($0)
}
let nonce = Bytes(sealedBox.nonce)
let chacha = try ChaChaPoly(key, nonce)
var ct = Bytes(sealedBox.ciphertext)

// ct contains the ciphertext

let ok = chacha.decrypt(&ct, Bytes(sealedBox.tag), aad)
print(String(bytes: ct, encoding: .utf8)!)
```
giving:
```swift
Hi, there
```
