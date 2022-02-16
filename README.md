# cordova-plugin-rsa

## Интеграция iOS
1) создать чистый апп или взять существующий
`cordova create cordova-rsa-app com.testing.rsa CordovaRSAApp`

2) в файлике config.xml в корне аппа добавить настройки платформы iOS (секция <platform name="ios">).
В частности Deployment Target и версию Swift.
Это важно, потому что зависимость SelfSignedCert.xcframework имеет DeploymentTarget iOS 13 и выше.

Итоговый файл может выглядеть примерно так:
```xml
<?xml version='1.0' encoding='utf-8'?>
<widget id="ru.bengus.rsa" version="1.0.0" xmlns="http://www.w3.org/ns/widgets" xmlns:cdv="http://cordova.apache.org/ns/1.0">
    <name>CordovaRSAApp</name>
    <description>Sample Apache Cordova App</description>
    <author email="dev@cordova.apache.org" href="https://cordova.apache.org">
        Apache Cordova Team
    </author>
    <content src="index.html" />
    <allow-intent href="http://*/*" />
    <allow-intent href="https://*/*" />
    <platform name="ios">
        <allow-intent href="itms:*" />
        <allow-intent href="itms-apps:*" />
        <!--Xcode project prefs-->
        <preference name="deployment-target" value="13.0" />
        <preference name="UseSwiftLanguageVersion" value="5" />
    </platform>
</widget>
```

3) затем в корне аппа добавить платформу iOS если она еще не добавлена ранее
`cordova platform add ios`

4) добавить плагин из git репозитория (есть возможность добавлять из ветки, для этого после .git добавьте без пробела #some_branch_or_tag)
`cordova plugin add 'https://github.com/ermashov/cordova-plugin-rsa.git'`

5) запустить Xcode и попробовать собрать и запустить

## Тестирование плагина на коленке

1) Написать отладочный код в index.js и вызвать cordova prepare, чтобы js обновился во всех добавленных платформах
👇👇👇 см содержимое www/js/index.js для тестирования плагина

```javascript
document.addEventListener('deviceready', onDeviceReady, false);

function testFunc() {
    // Testing login
    console.log('testing rsa plugin...');
    window.plugins.rsa.initialize(
        { alias: 'uassya' },
        function(certificate) {
            console.log('initialize ok');
            console.log(certificate);
        
            var myPemBase64 = certificate;
            // random valid recipient x509 for testing purposes
            var anotherPemBase64 = 'MIIEHzCCAwegAwIBAgIJANLrHjHg7T+RMA0GCSqGSIb3DQEBBQUAMHgxCzAJBgNVBAYTAlJVMQ8wDQYDVQQIDAZSdXNzaWExDzANBgNVBAcMBk1vc2NvdzEXMBUGA1UECgwOWkFPIEFrdGl2LVNvZnQxEDAOBgNVBAsMB1J1dG9rZW4xHDAaBgNVBAMME1J1dG9rZW4gVEVTVCBDQSBSU0EwHhcNMjEwMTE5MTA1ODA3WhcNMjIwMTE5MTA1ODA3WjA5MRMwEQYDVQQDDApCZW5ndXMgUlNBMQswCQYDVQQGEwJSVTEVMBMGA1UECAwM0JzQvtGB0LrQstCwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuwn81PW4Iv/9LxRE8QRKO9DUmyi2QcGZw8NzJawdvSSjxUKBPSrwAdHxEnRZIjtkDx7oocnHKKcVlr6In2W15Y1KioTT4Gs4Xfcp8QGkONV+6U3X043qmcBXBgvlt0ufq4n7XRqbZ+VhzlgKlwAaf+g2XuIA2XYANo19YzdvVZvoIUEgCdi+iSUKEl6EA94pU3GrstGWGwryR25ujS8ZkTihIfXdaHn03uFrPRb5CBrhnI7UinnfwqnO0TLOFtsthT/ijS0I80G+D7hWSQnigNqMacQTgyS+wBmGPIQje7F8YqZ25EKPgxj/1n3sPtbJ0QV8K+q3Y76lQr//Ea+F8wIDAQABo4HqMIHnMAsGA1UdDwQEAwIGwDATBgNVHSUEDDAKBggrBgEFBQcDBDATBgNVHSAEDDAKMAgGBiqFA2RxATAvBgUqhQNkbwQmDCTQodCa0JfQmCAi0KDRg9GC0L7QutC10L0g0K3QptCfIDIuMCIwOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovL3JhLnJ1dG9rZW4ucnUvcm9vdF9jZXJ0cy9yc2EuY3JsMEMGCCsGAQUFBwEBBDcwNTAzBggrBgEFBQcwAoYnaHR0cDovL3JhLnJ1dG9rZW4ucnUvcm9vdF9jZXJ0cy9yc2EuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQBoEJzH45sKP1dklsOwGzeewtEr7J//bSMTgvqqTVlrXcHor8bsaXI2DXNe89UjW1cPLaZISDqPePKrr2Pcrzbchl2E+pDAF5DK87oJTSF3Ov3ZWtXrZ82QA6oyfvO0Q7cRBmkxlT0NMtvi+ZQ5vZm8EWUo4mb3UNhddaMirvAv5WJo1iRVaoiXKRSJ18+z0ylLPiOtbE+xm9p98BKL+5SUtFIQhETnOMLreFZZBxQ0xUNDcfuGYTMBfsqURE39AX4kfLjmCQnHmCpTgC/feccPGKIlPngL0Alo24aLcHyrFVdyIxfIMx2lBXsV/XubZply/sRmWH4l6L8JGhpDKHpy';
            var data = 'Bengus';
            // Testing encrypt
            console.log('testing cmsEncrypt...');
            window.plugins.rsa.cmsEncrypt(
                {
                    certs: [
                        myPemBase64,
                        anotherPemBase64
                    ],
                    data: data
                },
                function(encryptedBase64) {
                    console.log('cmsEncrypt ok');
                    console.log(encryptedBase64);

                    // Testing decrypt
                    console.log('testing cmsDecrypt...');
                    window.plugins.rsa.cmsDecrypt(
                        {
                            alias: 'uassya',
                            data: encryptedBase64
                        },
                        function(decrypted) {
                            console.log('cmsDecrypt ok');
                            console.log(decrypted);
                        
                            // Testing sign
                            console.log('testing cmsSign...');
                            window.plugins.rsa.cmsSign(
                                {
                                    alias: 'uassya',
                                    data: data
                                },
                                function(signed) {
                                    console.log('cmsSign ok');
                                    console.log(signed);

                                    window.plugins.rsa.remove(
                                        { alias: 'uassya' },
                                        function() {
                                            console.log('remove ok');

                                            // this should be an error, because remove has been called
                                            window.plugins.rsa.getCertificate(
                                                { alias: 'uassya' },
                                                function(certificate2) {
                                                    console.log('getCertificate ok');
                                                    console.log(certificate2);
                                                },
                                                function(error) {
                                                    console.log(error);
                                                }
                                            );

                                        },
                                        function(error) {
                                            console.log(error);
                                        }
                                    );

                                },
                                function(error) {
                                    console.log(error);
                                }
                            );
                        
                        },
                        function(error) {
                            console.log(error);
                        }
                    );

                },
                function(error) {
                    console.log(error);
                }
            );
        
        },
        function(error) {
            console.log(error);
        }
    );
}

function onDeviceReady() {
    // Cordova is now initialized. Have fun!

    console.log('Running cordova-' + cordova.platformId + '@' + cordova.version);
    document.getElementById('deviceready').classList.add('ready');

    // initialize, getCertificate, remove, encrypt, decrypt and sign can be tested on tap to 'deviceready' indicator
    document.getElementById('deviceready').addEventListener('touchend', testFunc, false);
}
```


2) запустить приложение, с помощью Xcode в iOS симуляторе или с помощью консоли или Android Studio на Android эмуляторе

3) нажать на кнопку device ready и посмотреть в консоль вывода логов
