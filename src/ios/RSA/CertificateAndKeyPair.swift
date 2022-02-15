//
//  CertificateAndKeyPair.swift
//  rsa-swift
//
//  Created by Boris Bengus on 15.02.2022.
//

import Foundation
import Security

public class CertificateAndKeyPair {
    public let certificate: SecCertificate
    public let publicKey: SecKey
    public let privateKey: SecKey
    public let secIdentity: SecIdentity
    public let alias: String
    public let publicKeyKeychainTag: String
    /// For working with openssl
    public let privateKeyExternalRepresentation: Data
    /// For working with openssl
    public let x509CertificateData: Data
    
    public init(
        certificate: SecCertificate,
        publicKey: SecKey,
        privateKey: SecKey,
        secIdentity: SecIdentity,
        alias: String,
        publicKeyKeychainTag: String,
        privateKeyExternalRepresentation: Data
    ) {
        self.certificate = certificate
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.secIdentity = secIdentity
        self.alias = alias
        self.publicKeyKeychainTag = publicKeyKeychainTag
        self.privateKeyExternalRepresentation = privateKeyExternalRepresentation
        self.x509CertificateData = certificate.data
    }
}
