import Foundation
import LoggerAPI
import secp256k1

class ES256KSigner: SignerAlgorithm {
    let name: String = "ES256K"
    private let key: Data

    // Initialize a signer using .utf8 encoded PEM private key.
    init(key: Data) {
        self.key = key
    }

    // Sign the header and claims to produce a signed JWT String
    func sign(header: String, claims: String) throws -> String {
        let unsignedJWT = header + "." + claims
        guard let unsignedData = unsignedJWT.data(using: .utf8) else {
            throw JWTError.invalidJWTString
        }
        let signature = try sign(unsignedData)
        let signatureString = JWTEncoder.base64urlEncodedString(data: signature)
        return header + "." + claims + "." + signatureString
    }

    // send utf8 encoded `header.claims` to BlueECC for signing
    private func sign(_ data: Data) throws -> Data {
        guard let keyString = String(data: key, encoding: .utf8) else {
            throw JWTError.invalidPrivateKey
        }
        let privateKey = try secp256k1
            .Signing
            .PrivateKey(rawRepresentation: key)

        let signedData = try privateKey.ecdsa.signature(for: data)
        return signedData.rawRepresentation
    }
}

// Class for ECDSA verifying using BlueECC
@available(OSX 10.13, iOS 11, tvOS 11.0, watchOS 4.0, *)
class ES256KVerifier: VerifierAlgorithm {
    let name: String = "ES256K"
    private let key: Data

    // Initialize a verifier using .utf8 encoded PEM public key.
    init(key: Data) {
        self.key = key
    }

    // Verify a signed JWT String
    func verify(jwt: String) -> Bool {
        let components = jwt.components(separatedBy: ".")
        if components.count == 3 {
            guard let signature = JWTDecoder.data(base64urlEncoded: components[2]),
                let jwtData = (components[0] + "." + components[1]).data(using: .utf8)
                else {
                    return false
            }
            return self.verify(signature: signature, for: jwtData)
        } else {
            return false
        }
    }

    // Send the base64URLencoded signature and `header.claims` to BlueECC for verification.
    private func verify(signature: Data, for data: Data) -> Bool {
        do {
            let format: secp256k1.Format
            switch key[0] {
            case 0x02, 0x03:
                format = .compressed
            case 0x04:
                format = .uncompressed
            default:
                throw JWTError.failedVerification
            }
            let publicKey = try secp256k1
                .Signing
                .PublicKey(rawRepresentation: key, format: format)
            return publicKey
                .ecdsa
                .isValidSignature(
                    try .init(rawRepresentation: signature),
                    for: data
                )
        }
        catch {
            Log.error("Verification failed: \(error)")
            return false
        }
    }
}
