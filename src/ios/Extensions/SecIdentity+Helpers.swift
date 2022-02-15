//
//  SecIdentity+Helpers.swift
//  rsa-swift
//
//  Created by Boris Bengus on 15.02.2022.
//

import Foundation
import SelfSignedCert

extension SecIdentity {
    @discardableResult
    func deleteFromKeychain() -> Bool {
        let publicKeyTag = self.certificate?.publicKey?.keychainTag
        let privateKeyTag = self.privateKey?.keychainTag
        
        let deleteIdentityStatus = SecItemDelete([kSecValueRef as NSString: self] as CFDictionary)
        print(securityFrameworkError(status: deleteIdentityStatus))
        
        var deletePublicKeyStatus = errSecSuccess
        if
            let publicKeyTag = publicKeyTag,
            let publicKey = SecKey.loadFromKeychain(tag: publicKeyTag)
        {
            deletePublicKeyStatus = SecItemDelete([kSecValueRef as NSString: publicKey] as CFDictionary)
            print(securityFrameworkError(status: deletePublicKeyStatus))
        }
        
        var deletePrivateKeyStatus = errSecSuccess
        if
            let privateKeyTag = privateKeyTag,
            let privateKey = SecKey.loadFromKeychain(tag: privateKeyTag)
        {
            deletePrivateKeyStatus = SecItemDelete([kSecValueRef as NSString: privateKey] as CFDictionary)
            print(securityFrameworkError(status: deletePrivateKeyStatus))
        }
        
        let result = deleteIdentityStatus == errSecSuccess &&
        deletePublicKeyStatus == errSecSuccess &&
        deletePrivateKeyStatus == errSecSuccess
        
        return result
    }
}

private func securityFrameworkError(status: OSStatus) -> String {
    guard let string = SecCopyErrorMessageString(status, nil) else { return "unknown" }
    return string as String
}
