<h2><b>Description</b></h2>

SwiftChaChaPoly is a Swift implementation of Authenticated Encryption with Associated Data.
It is based on ChaCha20 encryption and Poly1305 authentication as defined in [RFC-7539].

<h2><b>Usage</b></h2>
In your project Package.swift file add a dependency like<br/>

	  dependencies: [
	  .package(url: "https://github.com/leif-ibsen/SwiftChaChaPoly", from: "1.1.0"),
	  ]

<h2><b>Example</b></h2>
    // This example is from section 2.8.2 in [RFC-7539].

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

    let chacha = ChaChaPoly(key, nonce)
    let tag = chacha.encrypt(&bytes, aad)
    print(tag)
    let ok = chacha.decrypt(&bytes, tag, aad)
    print(ok && bytes == Bytes(text.utf8) ? "Ok" : "Fail")

Giving

    [26, 225, 11, 89, 79, 9, 226, 106, 126, 144, 46, 203, 208, 96, 6, 145]
    Ok

<h2><b>Performance</b></h2>
The encryption and decryption speed was measured on a MacBook Pro 2018, 2,2 GHz 6-Core Intel Core i7. The results are:
<ul>
<li>Encryption: 192 MBytes / sec (11 cycles / byte)</li>
<li>Decryption: 213 MBytes / sec (10 cycles / byte)</li>
</ul> 

<h2><b>Dependencies</b></h2>

SwiftChaChaPoly requires Swift 5.0. It does not depend on other packages.

<h2><b>References</b></h2>

Algorithms from the following papers have been used in the implementation.
There are references in the source code where appropriate.

<ul>
<li>[FILIPPO] - Filippo Valsorda: A GO IMPLEMENTATION OF POLY1305 THAT MAKES SENSE, April 2019</li>
<li>[RFC-7539] - ChaCha20 and Poly1305 for IETF Protocols, May 2015</li>
</ul>
