//
//  OpenSSLWrapperError.swift
//  rsa-swift
//
//  Created by Boris Bengus on 14.02.2022.
//

import Foundation

public enum OpenSSLWrapperError: LocalizedError {
    case generalError
    case x509StackInitializationFailed
    case x509DeserializationFailed
    case evpPKeyDeserializationFailed
    case bioInitializationFailed
    case bioWritingFailed
    case cmsInitializationFailed
    case cmsDeserializationFailed
    case cmsEncryptFailed
    case cmsDecryptFailed
    case cmsSignFailed
    case unknown(reason: Error)
    
    public static func wrapError(_ error: Error) -> OpenSSLWrapperError {
        if let error = error as? OpenSSLWrapperError {
            return error
        } else {
            return .unknown(reason: error)
        }
    }
    
    
    // MARK: - LocalizedError
    public var errorDescription: String? {
        switch self {
        case .generalError:
            return "OpenSSL wrapper general error"
        case .x509StackInitializationFailed:
            return "Can't initialize new x509 stack. sk_X509_new_null returns nil"
        case .x509DeserializationFailed:
            return "Can't deserilize x509 from pem data. d2i_X509 returns nil"
        case .evpPKeyDeserializationFailed:
            return "Can't deserilize private key from data. d2i_PrivateKey returns nil"
        case .bioInitializationFailed:
            return "Can't initialize new BIO. BIO_new(BIO_s_mem()) returns nil"
        case .bioWritingFailed:
            return "Can't write Data to BIO. BIO_write written bytes count mismatch with original bytes count"
        case .cmsInitializationFailed:
            return "Can't initialize new CMS_ContentInfo. CMS_ContentInfo_new returns nil"
        case .cmsDeserializationFailed:
            return "Can't deserialize CMS_ContentInfo. d2i_CMS_bio returns nil"
        case .cmsEncryptFailed:
            return "Can't encrypt Data. CMS_encrypt returns nil and throws an error"
        case .cmsDecryptFailed:
            return "Can't decrypt Data. CMS_decrypt returns nil and throws an error"
        case .cmsSignFailed:
            return "Can't sign Data. CMS_sign returns nil and throws an error"
        case .unknown(let reason):
            return "PKCS11 unknown error: \(reason.localizedDescription)"
        }
    }
}
