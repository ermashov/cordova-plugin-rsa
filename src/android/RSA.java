package ru.rsa.plugins;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import android.security.KeyPairGeneratorSpec;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import java.security.cert.Certificate;
import java.util.List;


public class RSA {
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final Cipher CIPHER = getCipher();

    public static void createKeyPair(Context ctx,  String alias) throws Exception {
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

    public static boolean isEntryAvailable(String alias) {
        try {
            return loadKey(Cipher.ENCRYPT_MODE, alias) != null;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean deleteKeyPair(String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null, null);
        try {
            keyStore.deleteEntry(alias);
            return true;
        }  catch (Exception e) {
            Log.v("Error", e.getMessage());
            return true;
        }
    }

    private static Key loadKey(int cipherMode, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null, null);
        Key key;

        switch (cipherMode) {
            case 0:
            case Cipher.ENCRYPT_MODE:
                key = keyStore.getCertificate(alias).getPublicKey();
                if (key == null) {
                    throw new Exception("Failed to load the public key for " + alias);
                }
                break;
            case  Cipher.DECRYPT_MODE:
                key = keyStore.getKey(alias, null);
                if (key == null) {
                    throw new Exception("Failed to load the private key for " + alias);
                }
                break;
            default : throw new Exception("Invalid cipher mode parameter");
        }
        return key;
    }

    public static String getCertificate(String alias) throws Exception{
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null, null);
        Certificate cert = keyStore.getCertificate(alias);
        return Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP);
    }

    private static PrivateKey getPrivateKey(String alias) throws Exception{
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null, null);

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return privateKey;
    }

    public static String cmsSing(String alias, String data) throws Exception{

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null, null);

        Certificate cert = keyStore.getCertificate(alias);



        Log.v("RSAPlugin", "cmsSign 2.0.1");

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        Log.v("RSAPlugin", "cmsSign 2.0");
        //PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        //try {





            byte[] signedMessage = null;
            List<X509Certificate> certList = new ArrayList<X509Certificate>();
            CMSTypedData cmsData= new CMSProcessableByteArray(data.getBytes());
            certList.add((X509Certificate) cert);
            Store certs = new JcaCertStore(certList);
            CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
            ContentSigner contentSigner= new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
            cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC")
                            .build()).build(contentSigner, (X509Certificate) cert));
            cmsGenerator.addCertificates(certs);

            CMSSignedData cms = cmsGenerator.generate(cmsData, true);
            signedMessage = cms.getEncoded();

            Log.v("RSAPlugin signedMessage", Base64.encodeToString(signedMessage, Base64.NO_WRAP));


        return Base64.encodeToString(signedMessage, Base64.NO_WRAP);

        //RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();

/*
        Log.v("RSAPlugin", "cmsSign 2");

        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray(data.getBytes());

        Log.v("RSAPlugin", "cmsSign 3");

        certList.add(cert);

        Log.v("RSAPlugin", "cmsSign 3.1");

        Store certs = new JcaCertStore(certList);

        Log.v("RSAPlugin", "cmsSign 3.2");


        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        Log.v("RSAPlugin", "cmsSign 3.3");

        try {



              ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(privateKey);

            Log.v("RSAPlugin", "cmsSign 3.4");


            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                            .build(sha1Signer, (X509Certificate) cert));

            Log.v("RSAPlugin", "cmsSign 3.5");

            gen.addCertificates(certs);

            Log.v("RSAPlugin", "cmsSign 4");

            CMSSignedData sigData = gen.generate(msg, true);

            Log.v("RSAPlugin", "cmsSign 5");

            return Base64.encodeToString(sigData.getEncoded(), Base64.NO_WRAP);

        } catch (Exception e) {
            Log.v("RSAPlugin", e.getMessage());
        }*/


       // return "";
    }

    public static String cmsEncrypt(String certs, String data) throws Exception{

        String[] arCerts = certs.split(",");

        CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
        X509Certificate certificate;
        for(String pubKey : arCerts){
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Base64.decode(pubKey.getBytes("UTF-8"), Base64.NO_WRAP)));
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(certificate));
        }

        CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(new CMSProcessableByteArray(data.getBytes()),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_CBC)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build());

        //Log.v("RSAPlugin encrypt", Base64.encodeToString(cmsEnvelopedData.getEncoded(), Base64.NO_WRAP));

        return Base64.encodeToString(cmsEnvelopedData.getEncoded(), Base64.NO_WRAP);
    }

    public static String cmsDecrypt(String alias, String data) throws Exception{

        Security.addProvider(new BouncyCastleProvider());
        //try {
        CMSEnvelopedDataParser envDataParser = new CMSEnvelopedDataParser(Base64.decode(data, Base64.DEFAULT));
        RecipientInformationStore recipients =  envDataParser.getRecipientInfos();
        RecipientInformation recipient = (RecipientInformation) recipients.getRecipients().iterator().next();
        PrivateKey privateKey = RSA.getPrivateKey( alias);
        byte[] envelopedData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey));

        //String pDataBase64  =  new String(envelopedData, StandardCharsets.UTF_8);
        //Log.v("RSAPlugin d base64",  pDataBase64);

        //String pData = new String(Base64.decode(envelopedData, Base64.DEFAULT), StandardCharsets.UTF_8);
        //Log.v("RSAPlugin decrypt",  pData);

        return new String(envelopedData, StandardCharsets.UTF_8);
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