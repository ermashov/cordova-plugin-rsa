//
//  RSA.swift
//  rsa-swift
//
//  Created by Boris Bengus on 10.02.2022.
//

import Foundation
import OpenSSL
import SelfSignedCert

private enum Constants {
    static let RsaQueueLabel = "ru.eaasoft.plugins.RSA.SerialQueue"
    static let KeyAliasToTagMapUserDefaultsKey = "RSA.keyAliasToTagMap"
}

public class RSA {
    public static let shared = RSA()
    
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


    // MARK: - Public
    public init() { }
    
    
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
        let validTo = validFrom.addingTimeInterval(100 * 365 * 24 * 3600) // 100 years
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
    public func getCertificateAndKeyPairIfExists(alias: String) -> CertificateAndKeyPair? {
        if let cachedCertificateAndKeyPair = certificatesAndKeyPairsCache[alias] {
            return cachedCertificateAndKeyPair
        } else if let savedCertificateAndKeyPair = getSavedCertificateAndKeyPair(alias: alias) {
            return savedCertificateAndKeyPair 
        } else {
            return nil
        }
    }
    
    public func getOrCreateCertificateAndKeyPair(alias: String) -> Result<CertificateAndKeyPair, RSAError> {
        let certificateAndKeyPair: CertificateAndKeyPair
        if let existentCertificateAndKeyPair = getCertificateAndKeyPairIfExists(alias: alias) {
            certificateAndKeyPair = existentCertificateAndKeyPair
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
    
    public func deleteCertificateAndKeyPair(alias: String) -> Result<Void, RSAError> {
        // Clear cache for alias anyway
        certificatesAndKeyPairsCache.removeValue(forKey: alias)
        if
            let savedCertificateAndKeyPair = getSavedCertificateAndKeyPair(alias: alias),
            savedCertificateAndKeyPair.secIdentity.deleteFromKeychain()
        {
            // Update alias-to-keychainTag map after deletion
            var updatedMap = keyAliasToTagMap
            updatedMap.removeValue(forKey: alias)
            self.keyAliasToTagMap = updatedMap
            return .success(())
        } else {
            return .failure(RSAError.keyPairDeletionFailed)
        }
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
