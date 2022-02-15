//
//  RSAError.swift
//  rsa-swift
//
//  Created by Boris Bengus on 10.02.2022.
//

import Foundation

public enum RSAError: LocalizedError {
    case generalError
    case keyPairGenerationFailed
    case keyPairDeletionFailed
    case opensslError(reason: OpenSSLWrapperError)
    case unknown(reason: Error)
    
    public static func wrapError(_ error: Error) -> RSAError {
        if let error = error as? RSAError {
            return error
        } else {
            return .unknown(reason: error)
        }
    }
    
    
    // MARK: - LocalizedError
    public var errorDescription: String? {
        switch self {
        case .generalError:
            return "RSA general error"
        case .keyPairGenerationFailed:
            return "RSA key pair initialization failure"
        case .keyPairDeletionFailed:
            return "RSA key pair deletion failure"
        case .opensslError(let reason):
            return "Openssl error: \(reason.localizedDescription)"
        case .unknown(let reason):
            return "RSA unknown error: \(reason.localizedDescription)"
        }
    }
}
