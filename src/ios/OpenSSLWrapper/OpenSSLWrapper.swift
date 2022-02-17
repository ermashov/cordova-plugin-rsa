//
//  OpenSSLWrapper.swift
//  rsa-swift
//
//  Created by Boris Bengus on 10.02.2022.
//

import Foundation

public enum OpenSSLWrapper {
    // MARK: - Public
    public static func cmsEncrypt(
        _ document: Data,
        recipientX509Pems: [Data]
    ) throws -> Data {
        // Convert data to openssl format
        let bio = try getBIOFromData(document)
        defer {
            BIO_free(bio)
        }
        let recipientsX509Stack = try getX509StackFromPemDataArray(recipientX509Pems) 
        defer {
            sk_X509_pop_free(recipientsX509Stack, X509_free)
        }
        
        // Encrypt content
        let flags: Int32 = 0
        let cipher = EVP_des_cbc()
        guard let encryptedCms = CMS_encrypt(recipientsX509Stack, bio, cipher, UInt32(flags)) else {
            fputs("Error CMS_encrypt\n", stderr)
            ERR_print_errors_fp(stderr)
            throw OpenSSLWrapperError.cmsEncryptFailed
        }
        defer {
            CMS_ContentInfo_free(encryptedCms)
        }
        
        // Convert openssl result to Data
        let encryptedData = try getDataFromCMS(encryptedCms)
        
        return encryptedData
    }
    
    public static func cmsDecrypt(
        _ document: Data,
        x509PemData: Data,
        privateKeyData: Data
    ) throws -> Data
    {
        // Convert data to openssl format
        let encryptedCms = try getCMSFromData(document)
        defer {
            CMS_ContentInfo_free(encryptedCms)
        }
        let x509 = try getX509FromPemData(x509PemData)
        defer {
            X509_free(x509)
        }
        let evpPKey = try getEvpPKeyFromData(privateKeyData)
        defer {
            EVP_PKEY_free(evpPKey)
        }
        
        // Decrypt CMS
        guard let decryptedBio = BIO_new(BIO_s_mem()) else {
            throw OpenSSLWrapperError.bioInitializationFailed
        }
        defer {
            BIO_free(decryptedBio)
        }
        let r = CMS_decrypt(encryptedCms, evpPKey, x509, nil, decryptedBio, 0)
        guard r == 1 else {
            fputs("Error Decrypting Data\n", stderr)
            ERR_print_errors_fp(stderr)
            throw OpenSSLWrapperError.cmsDecryptFailed
        }
        
        // Convert openssl result to Data
        let decryptedData = getDataFromBio(decryptedBio)
        
        return decryptedData
    }
    
    public static func cmsSign(
        _ document: Data,
        x509PemData: Data,
        privateKeyData: Data
    ) throws -> Data
    {
        // convert data to openssl format
        let bio = try getBIOFromData(document)
        defer {
            BIO_free(bio)
        }
        let x509 = try getX509FromPemData(x509PemData)
        defer {
            X509_free(x509)
        }
        let evpPKey = try getEvpPKeyFromData(privateKeyData)
        defer {
            EVP_PKEY_free(evpPKey)
        }
        
        // Sign
        guard let signedCms = CMS_sign(x509, evpPKey, nil, bio, UInt32(CMS_BINARY | CMS_NOSMIMECAP)) else {
            throw OpenSSLWrapperError.cmsSignFailed
        }
        defer {
            CMS_ContentInfo_free(signedCms)
        }
        
        // Convert openssl result to Data
        let signedCmsData = try getDataFromCMS(signedCms)
        
        return signedCmsData
    }
    
    // MARK: - Private
    private static func getX509StackFromPemDataArray(_ pemDataArray: [Data]) throws -> OpaquePointer {
        guard let recipientsX509Stack = sk_X509_new_null() else {
            throw OpenSSLWrapperError.x509StackInitializationFailed
        }
        for pemData in pemDataArray {
            let x509 = try getX509FromPemData(pemData)
            sk_X509_push(recipientsX509Stack, x509)
        }
        return recipientsX509Stack
    }
    
    private static func getX509FromPemData(_ pemData: Data) throws -> OpaquePointer {
        try pemData.withUnsafeBytes {
            var pointer: UnsafePointer<UInt8>? = $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
            guard let x509 = d2i_X509(nil, &pointer, pemData.count) else {
                throw OpenSSLWrapperError.x509DeserializationFailed
            }
            return x509
        }
    }
    
    private static func getEvpPKeyFromData(_ pKeyData: Data) throws -> OpaquePointer {
        try pKeyData.withUnsafeBytes {
            var pointer: UnsafePointer<UInt8>? = $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
            guard let evpPKey = d2i_PrivateKey(EVP_PKEY_RSA, nil, &pointer, pKeyData.count) else {
                throw OpenSSLWrapperError.evpPKeyDeserializationFailed
            }
            return evpPKey
        }
    }
    
    private static func getDataFromBio(_ bio: OpaquePointer) -> Data {
        var bytesPtr: UnsafeMutableRawPointer?
        let bytesLength = BIO_ctrl(bio, BIO_CTRL_INFO, 0, &bytesPtr)
        let data = Data(bytes: bytesPtr!, count: bytesLength)
        return data
    }
    
    private static func getBIOFromData(_ data: Data) throws -> OpaquePointer {
        // document bio
        guard let bio = BIO_new(BIO_s_mem()) else {
            throw OpenSSLWrapperError.bioInitializationFailed
        }
        try data.withUnsafeBytes {
            let pointer = $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
            let res = BIO_write(bio, pointer, Int32(data.count))
            if res != data.count {
                throw OpenSSLWrapperError.bioWritingFailed
            }
        }
        return bio
    }
    
    private static func getDataFromCMS(_ cms: OpaquePointer) throws -> Data {
        let cmsLength = i2d_CMS_ContentInfo(cms, nil)
        var cmsData = Data(repeating: 0x00, count: Int(cmsLength))
        cmsData.withUnsafeMutableBytes {
            var pointer = $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
            i2d_CMS_ContentInfo(cms, &pointer)
        }
        return cmsData
    }
    
    private static func getCMSFromData(_ data: Data) throws -> OpaquePointer {
        try data.withUnsafeBytes {
            var pointer: UnsafePointer<UInt8>? = $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
            guard let cmsContentInfo = d2i_CMS_ContentInfo(nil, &pointer, data.count) else {
                throw OpenSSLWrapperError.cmsDeserializationFailed
            }
            return cmsContentInfo
        }
    }
}
