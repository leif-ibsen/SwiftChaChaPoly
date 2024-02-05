//
//  ChaChaPoly.swift
//  SwiftChaChaPoly
//
//  Created by Leif Ibsen on 01/10/2020.
//

/// Unsigned 8 bit value
public typealias Byte = UInt8
/// Array of unsigned 8 bit values
public typealias Bytes = [UInt8]

/// The ChaChaPoly structure
public struct ChaChaPoly {
    
    // MARK: Exceptions

    ///
    /// ChaChaPoly exceptions
    ///
    public enum Ex: Error, CustomStringConvertible {

        /// Textual description of `self`
        public var description: String {
            switch self {
            case .keySize:
                return "Wrong key size - must be 32"
            case .nonceSize:
                return "Wrong nonce size - must be 12"
            }
        }

        /// Wrong key size - must be 32
        case keySize
        /// Wrong nonce size - must be 12
        case nonceSize
    }


    // MARK: Properties
    
    /// The key - a 32 byte value
    public internal(set) var key: Bytes

    /// The nonce - a 12 byte value
    public internal(set) var nonce: Bytes


    // MARK: - Constructor

    /// Constructs a ChaChaPoly instance from key and nonce
    ///
    /// - Parameters:
    ///   - key: The key - a 32 byte value
    ///   - nonce: The nonce - a 12 byte value
    /// - Throws: An exception if `key` or `nonce` has wrong size
    public init(_ key: Bytes, _ nonce: Bytes) throws {
        guard key.count == 32 else {
            throw Ex.keySize
        }
        guard nonce.count == 12 else {
            throw Ex.nonceSize
        }
        self.key = key
        self.nonce = nonce
    }


    // MARK: Methods
    
    /// Encrypts a byte array and computes the tag
    ///
    /// - Parameters:
    ///   - plaintext: The bytes to encrypt - it is replaced with the corresponding ciphertext of the same length
    ///   - aad: The additional authenticated data - the default value is an empty array
    /// - Returns: The tag computed from `plaintext` and `aad` - a 16 byte value
    public func encrypt(_ plaintext: inout Bytes, _ aad: Bytes = []) -> Bytes {
        let chacha = ChaCha20(self.key, self.nonce)
        chacha.encrypt(&plaintext)
        var aead = Bytes(repeating: 0, count: 16 * ((aad.count + 15) / 16) + 16 * ((plaintext.count + 15) / 16) + 16)
        for i in 0 ..< aad.count {
            aead[i] = aad[i]
        }
        let n = 16 * ((aad.count + 15) / 16)
        for i in 0 ..< plaintext.count {
            aead[n + i] = plaintext[i]
        }
        let m = 16 * ((plaintext.count + 15) / 16)
        int2bytes(aad.count, &aead, n + m)
        int2bytes(plaintext.count, &aead, n + m + 8)
        return Poly1305(makePolyKey()).computeTag(aead)
    }

    /// Decrypts a byte array and verifies the tag
    ///
    /// - Parameters:
    ///   - ciphertext: The bytes to decrypt - if `tag` is verified, it is replaced with the corresponding plaintext
    ///   - tag: The tag to verify against `ciphertext` and `aad` - a 16 byte value
    ///   - aad: The additional authenticated data - the default value is an empty array
    /// - Returns: `true` if `tag` is verified, else `false`
    public func decrypt(_ ciphertext: inout Bytes, _ tag: Bytes, _ aad: Bytes = []) -> Bool {
        let n = 16 * ((aad.count + 15) / 16)
        let m = 16 * ((ciphertext.count + 15) / 16)
        var aead = Bytes(repeating: 0, count: n + m + 16)
        for i in 0 ..< aad.count {
            aead[i] = aad[i]
        }
        for i in 0 ..< ciphertext.count {
            aead[n + i] = ciphertext[i]
        }
        int2bytes(aad.count, &aead, n + m)
        int2bytes(ciphertext.count, &aead, n + m + 8)
        if Poly1305(makePolyKey()).computeTag(aead) == tag {
            let chacha = ChaCha20(self.key, self.nonce)
            chacha.encrypt(&ciphertext)
            return true
        }
        return false
    }
    
    func int2bytes(_ x: Int, _ bytes: inout Bytes, _ n: Int) {
        bytes[n] = Byte(x & 0xff)
        bytes[n + 1] = Byte((x >> 8) & 0xff)
        bytes[n + 2] = Byte((x >> 16) & 0xff)
        bytes[n + 3] = Byte((x >> 24) & 0xff)
        bytes[n + 4] = Byte((x >> 32) & 0xff)
        bytes[n + 5] = Byte((x >> 40) & 0xff)
        bytes[n + 6] = Byte((x >> 48) & 0xff)
        bytes[n + 7] = Byte((x >> 56) & 0xff)
    }

    func makePolyKey() -> (r0: Limb, r1: Limb, s0: Limb, s1: Limb) {
        var x = Words(repeating: 0, count: 16)
        ChaCha20(self.key, self.nonce).blockFunction(&x, 0)
        return ((Limb(x[1]) << 32 | Limb(x[0])) & 0x0ffffffc0fffffff, (Limb(x[3]) << 32 | Limb(x[2])) & 0x0ffffffc0ffffffc, Limb(x[5]) << 32 | Limb(x[4]), Limb(x[7]) << 32 | Limb(x[6]))
    }

}
