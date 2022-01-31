package ru.cordova.rsa.plugins;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import android.security.KeyPairGeneratorSpec;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import java.security.cert.Certificate;

public class RSA {
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final Cipher CIPHER = getCipher();

    public static void createKeyPair(Context ctx, String alias) throws Exception {
        Calendar notBefore = Calendar.getInstance();
        Calendar notAfter = Calendar.getInstance();
        notAfter.add(Calendar.YEAR, 100);
        String principalString = String.format("CN=%s, OU=%s", alias, ctx.getPackageName());
        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec
            .Builder(ctx)
            .setAlias(alias)
            .setSubject(new X500Principal(principalString))
            .setSerialNumber(BigInteger.ONE)
            .setStartDate(notBefore.getTime())
            .setEndDate(notAfter.getTime())
            .setEncryptionRequired()
            .setKeySize(2048)
            .setKeyType("RSA")
            .build();
        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA", KEYSTORE_PROVIDER);
        kpGenerator.initialize(spec);
        kpGenerator.generateKeyPair();
    }

    public static String getPublicKey(String alias) throws Exception{
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null, null);
        Certificate cert = keyStore.getCertificate(alias);
        return Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP);
    }

    public static PrivateKey getPrivateKey(String alias) throws Exception{
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null, null);

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return privateKey;
    }


    private static Cipher getCipher() {
        try {
           // return Cipher.getInstance("DES/CBC/PKCS5Padding");
           return Cipher.getInstance("RSA/ECB/PKCS1Padding");

        } catch (Exception e) {
            return null;
        }
    }
}