//
//  RSAPlugin.swift
//  rsa-swift
//
//  Created by Boris Bengus on 15.02.2022.
//

import Foundation

@objc(RSAPlugin) 
class RSAPlugin: CDVPlugin {
    private lazy var jsonEncoder = JSONEncoder()

    
    // MARK: - Plugin initialization
    override func pluginInitialize() {
        super.pluginInitialize()
        // Do smth on plugin initialization
    }
    
    
    // MARK: - Plugin commands
    @objc(initialize:)
    func initialize(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            
            guard let alias = command.arguments[0] as? String else {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "use { alias: 'string' }."),
                    callbackId: command.callbackId
                )
                return
            }
            let pluginResult: CDVPluginResult
            switch RSA.shared.getX509CertificatePem(alias: alias) {
            case .success(let x509PemData):
                pluginResult = CDVPluginResult(
                    status: .ok,
                    messageAs: x509PemData.base64EncodedString()
                )
            case .failure(let error):
                pluginResult = CDVPluginResult(
                    status: .error,
                    messageAs: error.localizedDescription
                )
            }
            self.commandDelegate?.send(pluginResult, callbackId: command.callbackId)
        }
    }

    @objc(getCertificate:)
    func getCertificate(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            
            guard let alias = command.arguments[0] as? String else {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "use { alias: 'string' }."),
                    callbackId: command.callbackId
                )
                return
            }

            if !RSA.shared.isCertificateAndKeyPairExists(alias: alias) {
                self.commandDelegate?.send(
                    CDVPluginResult(
                        status: .error,
                        messageAs: "Certificate and key pair doesn't exist"
                    ), 
                    callbackId: command.callbackId
                )
                return
            }

            let pluginResult: CDVPluginResult
            switch RSA.shared.getX509CertificatePem(alias: alias) {
            case .success(let x509PemData):
                pluginResult = CDVPluginResult(
                    status: .ok,
                    messageAs: x509PemData.base64EncodedString()
                )
            case .failure(let error):
                pluginResult = CDVPluginResult(
                    status: .error,
                    messageAs: error.localizedDescription
                )
            }
            self.commandDelegate?.send(pluginResult, callbackId: command.callbackId)
        }
    }
    
    @objc(remove:)
    func remove(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            
            guard let alias = command.arguments[0] as? String else {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "use { alias: 'string' }."),
                    callbackId: command.callbackId
                )
                return
            }
            let pluginResult: CDVPluginResult
            switch RSA.shared.deleteCertificateAndKeyPair(alias: alias) {
            case .success:
                pluginResult = CDVPluginResult(
                    status: .ok,
                    messageAs: "ok"
                )
            case .failure(let error):
                pluginResult = CDVPluginResult(
                    status: .error,
                    messageAs: error.localizedDescription
                )
            }
            self.commandDelegate?.send(pluginResult, callbackId: command.callbackId)
        }
    }
    
    @objc(cmsEncrypt:)
    func cmsEncrypt(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            
            guard
                let certStrings = command.arguments[0] as? [String],
                let dataString = command.arguments[1] as? String,
                let data = dataString.data(using: .utf8) else
            {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "use { certs: ['', '', ...], data: 'utf-8 string for encrypting' }."),
                    callbackId: command.callbackId
                )
                return
            }
            let recipientPems = certStrings.compactMap { Data(base64Encoded: $0) }
            guard !recipientPems.isEmpty else {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "wrong base64 pems sent to certs param."),
                    callbackId: command.callbackId
                )
                return
            }
            
            RSA.shared.cmsEncrypt(
                data,
                recipientX509Pems: recipientPems
            ) { [weak self] result in
                guard let self = self else { return }

                let pluginResult: CDVPluginResult
                switch result {
                case .success(let encryptedData):
                    pluginResult = CDVPluginResult(
                        status: .ok,
                        messageAs: encryptedData.base64EncodedString()
                    )
                case .failure(let error):
                    pluginResult = CDVPluginResult(
                        status: .error,
                        messageAs: error.localizedDescription
                    )
                }
                self.commandDelegate?.send(pluginResult, callbackId: command.callbackId)
            }
        }
    }
    
    @objc(cmsDecrypt:)
    func cmsDecrypt(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            
            guard
                let alias = command.arguments[0] as? String,
                let base64String = command.arguments[1] as? String,
                let data = Data(base64Encoded: base64String) else
            {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "use { alias: 'string', data: 'encrypted base64' }."),
                    callbackId: command.callbackId
                )
                return
            }

            let certificateAndKeyPair: CertificateAndKeyPair
            switch RSA.shared.getCertificateAndKeyPair(alias: alias) {
            case .success(let cert):
                certificateAndKeyPair = cert
            case .failure(let error):
                self.commandDelegate?.send(
                    CDVPluginResult(
                        status: .error,
                        messageAs: error.localizedDescription
                    ),
                    callbackId: command.callbackId
                )
                return
            }
            
            RSA.shared.cmsDecrypt(
                x509PemData: certificateAndKeyPair.x509CertificateData,
                privateKeyData: certificateAndKeyPair.privateKeyExternalRepresentation,
                data: data
            ) { [weak self] result in
                guard let self = self else { return }

                let pluginResult: CDVPluginResult
                switch result {
                case .success(let decryptedData):
                    pluginResult = CDVPluginResult(
                        status: .ok,
                        messageAs: String(data: decryptedData, encoding: .utf8)
                    )
                case .failure(let error):
                    pluginResult = CDVPluginResult(
                        status: .error,
                        messageAs: error.localizedDescription
                    )
                }
                self.commandDelegate?.send(pluginResult, callbackId: command.callbackId)
            }
        }
    }
    
    @objc(cmsSign:)
    func cmsSign(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            
            guard
                let alias = command.arguments[0] as? String,
                let dataString = command.arguments[1] as? String,
                let data = dataString.data(using: .utf8) else
            {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "use { alias: 'string', data: 'utf-8 string for signing' }."),
                    callbackId: command.callbackId
                )
                return
            }

            let certificateAndKeyPair: CertificateAndKeyPair
            switch RSA.shared.getCertificateAndKeyPair(alias: alias) {
            case .success(let cert):
                certificateAndKeyPair = cert
            case .failure(let error):
                self.commandDelegate?.send(
                    CDVPluginResult(
                        status: .error,
                        messageAs: error.localizedDescription
                    ),
                    callbackId: command.callbackId
                )
                return
            }
            
            RSA.shared.cmsSign(
                x509PemData: certificateAndKeyPair.x509CertificateData,
                privateKeyData: certificateAndKeyPair.privateKeyExternalRepresentation,
                data: data
            ) { [weak self] result in
                guard let self = self else { return }

                let pluginResult: CDVPluginResult
                switch result {
                case .success(let signedData):
                    pluginResult = CDVPluginResult(
                        status: .ok,
                        messageAs: signedData.base64EncodedString()
                    )
                case .failure(let error):
                    pluginResult = CDVPluginResult(
                        status: .error,
                        messageAs: error.localizedDescription
                    )
                }
                self.commandDelegate?.send(pluginResult, callbackId: command.callbackId)
            }
        }
    }
    
    
    // MARK: - Private
    private func wrongParamsResult(message: String) -> CDVPluginResult {
        return CDVPluginResult(
            status: .error,
            messageAs: "Wrong params error: \(message)"
        )
    }
}
