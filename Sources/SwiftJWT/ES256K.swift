import Foundation
import LoggerAPI
import secp256k1
import CryptoKit

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
            throw JWTError.invalidUTF8Data
        }
        let keyData = try stripKeyFromPEM(pem: keyString)
        let privateKey = try secp256k1
            .Signing
            .PrivateKey(rawRepresentation: keyData)

        let (r, s) = extractRS(from: try privateKey.ecdsa.signature(for: data).rawRepresentation)

        // For some reason secp256k1 reverses the bytes of R/S. This fixes that and allows this signature to be valid in bouncy castle.

        return Data(r.reversed()) + Data(s.reversed())
    }

    private func extractRS(from signature: Data) -> (r: Data, s: Data) {
        let rIndex = signature.startIndex
        let sIndex = signature.index(rIndex, offsetBy: 32)
        let r = signature[rIndex..<sIndex]
        let s = signature[sIndex..<signature.endIndex]
        return (r, s)
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

    // Send the base64URLencoded signature and `header.claims` to libsecp256k1 for verification.
    private func verify(signature: Data, for data: Data) -> Bool {
        do {
            guard let keyString = String(data: key, encoding: .utf8) else {
                throw JWTError.invalidUTF8Data
            }
            let keyData = try stripKeyFromPEM(pem: keyString)
            let format: secp256k1.Format
            switch keyData[0] {
            case 0x02, 0x03:
                format = .compressed
            case 0x04:
                format = .uncompressed
            default:
                throw JWTError.failedVerification
            }

            let publicKey = try secp256k1
                .Signing
                .PublicKey(rawRepresentation: keyData, format: format)
            let signatureRaw = try secp256k1.Signing.ECDSASignature(rawRepresentation: signature)
            let verification =  publicKey
                .ecdsa
                .isValidSignature(signatureRaw, for: data)

            return verification
        }
        catch {
            Log.error("Verification failed: \(error)")
            return false
        }
    }
}

private func stripKeyFromPEM(pem: String) throws -> Data {
    let strippedKey = String(pem.filter { !" \n\t\r".contains($0) })
    let pemComponents = strippedKey.components(separatedBy: "-----")
    guard pemComponents.count == 5 else {
        throw JWTError.missingPEMHeaders
    }
    guard let der = Data(base64Encoded: pemComponents[2]) else {
        throw JWTError.missingPEMHeaders
    }
    return der
}
