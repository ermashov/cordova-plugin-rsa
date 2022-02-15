//
//  SecKey+Helpers.swift
//  rsa-swift
//
//  Created by Boris Bengus on 15.02.2022.
//

import Foundation

extension SecKey {
    func externalRepresentation() -> Data? {
        var error: Unmanaged<CFError>?
        let data = SecKeyCopyExternalRepresentation(self, &error)
        return data as Data?
    }
}
