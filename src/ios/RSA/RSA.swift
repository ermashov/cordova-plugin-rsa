//
//  RSA.swift
//  rsa-swift
//
//  Created by Boris Bengus on 10.02.2022.
//

import Foundation
import OpenSSL

private enum Constants {
    static let RsaQueueLabel = "ru.eaasoft.plugins.RSA.SerialQueue"
    static let KeyAliasToTagMapUserDefaultsKey = "RSA.keyAliasToTagMap"
}

public class RSA {
    static let shared = RSA()
    
    private let serialQueue = DispatchQueue(label: Constants.RsaQueueLabel)
    private let callbackQueue = DispatchQueue.main
    private var keyAliasToTagMap: [String: String] {
        get {
            if
                let string = UserDefaults.standard.string(forKey: Constants.KeyAliasToTagMapUserDefaultsKey),
                let data = string.data(using: .utf8),
                let map = try? JSONDecoder().decode([String: String].self, from: data)
            {
                return map
            } else {
                return [:]
            }
        }
        set {
            if
                let data = try? JSONEncoder().encode(newValue),
                let string = String(data: data, encoding: .utf8)
            {
                UserDefaults.standard.set(string, forKey: Constants.KeyAliasToTagMapUserDefaultsKey)
            }
        }
    }
    private var certificatesAndKeyPairsCache = [String: CertificateAndKeyPair]()
    
    
    // MARK: - Private
    private func getSavedCertificateAndKeyPair(alias: String) -> CertificateAndKeyPair? {
        if
            let tag = self.keyAliasToTagMap[alias],
            let loadedPublicKey = SecKey.loadFromKeychain(tag: tag),
            let loadedIdentity = SecIdentity.find(withPublicKey: loadedPublicKey),
            let publicKeyKeychainTag = loadedIdentity.certificate?.publicKey?.keychainTag,
            let certificate = loadedIdentity.certificate,
            let publicKey = loadedIdentity.certificate?.publicKey,
            let privateKey = loadedIdentity.privateKey,
            let privateKeyExternalRepresentation = privateKey.externalRepresentation()
        {
            return CertificateAndKeyPair(
                certificate: certificate,
                publicKey: publicKey,
                privateKey: privateKey,
                secIdentity: loadedIdentity,
                alias: alias,
                publicKeyKeychainTag: publicKeyKeychainTag,
                privateKeyExternalRepresentation: privateKeyExternalRepresentation
            )
        } else {
            return nil
        }
    }
    
    private func createCertificateAndKeyPair(alias: String) throws -> CertificateAndKeyPair {
        let validFrom = Date()
        let validTo = validFrom.addingTimeInterval(100*365*24*3600) // 100 years
        guard
            let identity = SecIdentity.create(
                ofSize: 2048,
                subjectCommonName: alias,
                subjectEmailAddress: "test@example.com",
                validFrom: validFrom,
                validTo: validTo
            ),
            let publicKeyKeychainTag = identity.certificate?.publicKey?.keychainTag,
            let certificate = identity.certificate,
            let publicKey = identity.certificate?.publicKey,
            let privateKey = identity.privateKey,
            let privateKeyExternalRepresentation = privateKey.externalRepresentation() else
        {
            throw RSAError.keyPairGenerationFailed
        }
        return CertificateAndKeyPair(
            certificate: certificate,
            publicKey: publicKey,
            privateKey: privateKey,
            secIdentity: identity,
            alias: alias,
            publicKeyKeychainTag: publicKeyKeychainTag,
            privateKeyExternalRepresentation: privateKeyExternalRepresentation
        )
    }
    
    
    // MARK: - Public
    public func isCertificateAndKeyPairExists(alias: String) -> Bool {
        return getSavedCertificateAndKeyPair(alias: alias) != nil
    }
    
    public func getCertificateAndKeyPair(alias: String) -> Result<CertificateAndKeyPair, RSAError> {
        let certificateAndKeyPair: CertificateAndKeyPair
        if let cachedCertificateAndKeyPair = certificatesAndKeyPairsCache[alias] {
            certificateAndKeyPair = cachedCertificateAndKeyPair
        } else if let savedCertificateAndKeyPair = getSavedCertificateAndKeyPair(alias: alias) {
            certificateAndKeyPair = savedCertificateAndKeyPair 
        } else {
            do {
                certificateAndKeyPair = try createCertificateAndKeyPair(alias: alias)
            } catch {
                let error = RSAError.wrapError(error)
                return .failure(error)
            }
            // Update alias-to-keychainTag map after keypair generation
            var updatedMap = keyAliasToTagMap
            updatedMap[alias] = certificateAndKeyPair.publicKeyKeychainTag
            self.keyAliasToTagMap = updatedMap
        }
        // Update loaded certificates and keypairs cache
        self.certificatesAndKeyPairsCache[alias] = certificateAndKeyPair
        return .success(certificateAndKeyPair)
    }
    
    public func getX509CertificatePem(alias: String) -> Result<Data, RSAError> {
        switch getCertificateAndKeyPair(alias: alias) {
        case .success(let certificateAndKeyPair):
            return .success(certificateAndKeyPair.certificate.data)
        case .failure(let error):
            return .failure(error)
        }
    }
    
    public func deleteCertificateAndKeyPair(alias: String) -> Result<Void, RSAError> {
        if let savedCertificateAndKeyPair = getSavedCertificateAndKeyPair(alias: alias) {
            if savedCertificateAndKeyPair.secIdentity.deleteFromKeychain() {
                return .success(())
            } else {
                return .failure(RSAError.keyPairGenerationFailed)
            }
        }
        // Nothing to delete
        return .success(())
    }
    
    public func cmsEncrypt(
        _ data: Data,
        recipientX509Pems: [Data],
        completion: @escaping (Result<Data, RSAError>) -> Void
    ) {
        serialQueue.async {
            do {
                let encryptedData = try OpenSSLWrapper.cmsEncrypt(
                    data,
                    recipientX509Pems: recipientX509Pems
                )
                self.callbackQueue.async {
                    completion(.success(encryptedData))
                }
            } catch {
                self.callbackQueue.async {
                    let opensslError = OpenSSLWrapperError.wrapError(error)
                    let wrappedError = RSAError.opensslError(reason: opensslError)
                    completion(.failure(wrappedError))
                }
            }
        }
    }
    
    public func cmsDecrypt(
        x509PemData: Data,
        privateKeyData: Data,
        data: Data,
        completion: @escaping (Result<Data, RSAError>) -> Void
    ) {
        serialQueue.async {
            do {
                let decryptedData = try OpenSSLWrapper.cmsDecrypt(
                    data,
                    x509PemData: x509PemData,
                    privateKeyData: privateKeyData
                )
                self.callbackQueue.async {
                    completion(.success(decryptedData))
                }
            } catch {
                self.callbackQueue.async {
                    let opensslError = OpenSSLWrapperError.wrapError(error)
                    let wrappedError = RSAError.opensslError(reason: opensslError)
                    completion(.failure(wrappedError))
                }
            }
        }
    }

    public func cmsSign(
        x509PemData: Data,
        privateKeyData: Data,
        data: Data,
        completion: @escaping (Result<Data, RSAError>) -> Void
    ) {
        serialQueue.async {
            do {
                let signedData = try OpenSSLWrapper.cmsSign(
                    data,
                    x509PemData: x509PemData,
                    privateKeyData: privateKeyData
                )
                self.callbackQueue.async {
                    completion(.success(signedData))
                }
            } catch {
                self.callbackQueue.async {
                    let opensslError = OpenSSLWrapperError.wrapError(error)
                    let wrappedError = RSAError.opensslError(reason: opensslError)
                    completion(.failure(wrappedError))
                }
            }
        }
    }
}