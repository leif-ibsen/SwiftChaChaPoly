# ``SwiftChaChaPoly``

Authenticated Encryption with Associated Data

## Overview

SwiftChaChaPoly implements Authenticated Encryption with Associated Data as defined in [RFC 8439].

It is based on the ChaCha20 stream cipher and Poly1305 authentication.

### Example

```swift
import SwiftChaChaPoly

// This example is from section 2.8.2 in [RFC 8439].

let key: Bytes = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f]
let nonce: Bytes = [
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]
let aad: Bytes = [
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7]
let text = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

var bytes = Bytes(text.utf8)

let chacha = try ChaChaPoly(key, nonce)
let tag = chacha.encrypt(&bytes, aad)
print(tag)
let ok = chacha.decrypt(&bytes, tag, aad)
print(ok && bytes == Bytes(text.utf8) ? "Ok" : "Fail")
```
Giving
```swift
[26, 225, 11, 89, 79, 9, 226, 106, 126, 144, 46, 203, 208, 96, 6, 145]
Ok
```

### Usage

To use SwiftChaChaPoly, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftChaChaPoly", from: "2.4.0"),
]
```

SwiftChaChaPoly itself does not depend on other packages.

> Important:
SwiftChaChaPoly requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

## Topics

### Structures

- ``ChaChaPoly``

### Type Aliases

- ``SwiftChaChaPoly/Byte``
- ``SwiftChaChaPoly/Bytes``

### Additional Information

- <doc:CryptoKit>
- <doc:Performance>
- <doc:References>

