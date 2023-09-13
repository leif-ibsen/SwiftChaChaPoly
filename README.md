<h2><b>SwiftChaChaPoly</b></h2>
<h3><b>Contents:</b></h3>
<ul>
<li><a href="#use">Usage</a></li>
<li><a href="#ex">Example</a></li>
<li><a href="#comp">CryptoKit Compatibility</a></li>
<li><a href="#perf">Performance</a></li>
<li><a href="#dep">Dependencies</a></li>
<li><a href="#ref">References</a></li>
</ul>

SwiftChaChaPoly implements Authenticated Encryption with Associated Data as defined in [RFC-8439].
It is based on the ChaCha20 stream cipher and Poly1305 authentication.
<h2><b>Usage</b></h2>
In your project Package.swift file add a dependency like<br/>

	  dependencies: [
	  .package(url: "https://github.com/leif-ibsen/SwiftChaChaPoly", from: "2.0.0"),
	  ]

<h2 id="ex"><b>Example</b></h2>
    // This example is from section 2.8.2 in [RFC-8439].

    import SwiftChaChaPoly

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

Giving

    [26, 225, 11, 89, 79, 9, 226, 106, 126, 144, 46, 203, 208, 96, 6, 145]
    Ok

<h2 id="comp"><b>Compatibility with Apple's CryptoKit Framework</b></h2>
SwiftChaChaPoly is compatible with CryptoKit as the following examples show:

<h3><b>Example 1: SwiftChaChaPoly encrypts, CryptoKit opens</b></h3>
    
    import CryptoKit

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

giving:

    Hi, there

<h3><b>Example 2: CrypotoKit seals, SwiftChaChaPoly decrypts</b></h3>
        
    import CryptoKit

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

giving:

    Hi, there

<h2 id="perf"><b>Performance</b></h2>
The encryption and decryption speed was measured on a iMac 2021, Apple M1 chip. The results are:
<ul>
<li>Encryption: 290 MBytes / sec (11 cycles / byte)</li>
<li>Decryption: 290 MBytes / sec (11 cycles / byte)</li>
</ul> 

<h2 id="dep"><b>Dependencies</b></h2>

SwiftChaChaPoly requires Swift 5.0. It does not depend on other packages.

<h2 id="ref"><b>References</b></h2>

Algorithms from the following papers have been used in the implementation.
There are references in the source code where appropriate.

<ul>
<li>[FILIPPO] - Filippo Valsorda: A GO IMPLEMENTATION OF POLY1305 THAT MAKES SENSE, April 2019</li>
<li>[RFC-8439] - ChaCha20 and Poly1305 for IETF Protocols, June 2018</li>
</ul>
