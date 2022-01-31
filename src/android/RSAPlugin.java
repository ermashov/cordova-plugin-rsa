package ru.rsa.plugins;


import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
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
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
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
import org.json.JSONArray;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import com.sun.jna.NativeLong;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class RSAPlugin extends CordovaPlugin {


    public RSAPlugin() {}

    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) {

        Context context = this.cordova.getActivity().getApplicationContext();

        if (action.equals("init"))
        {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        String alias = args.getString(0);
                        if (!RSA.isEntryAvailable(alias)) {
                            RSA.createKeyPair(cordova.getActivity().getApplicationContext(), alias);
                        }
                        Log.v("New privete key", RSA.getPublicKey(alias));
                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, new String("ok"));
                        callbackContext.sendPluginResult(pluginResult);

                    } catch (Exception e) {
                        callbackContext.error("token error ex.");

                    }

                }
            });

            return true;

        }else if (action.equals("getPublicKey"))
        {

            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {

                        String alias = args.getString(0);

                        String publicKey = RSA.getPublicKey(alias);

                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, publicKey);
                        callbackContext.sendPluginResult(pluginResult);

                    } catch (Exception e) {
                        callbackContext.error("token error ex.");

                    }

                }
            });

            return true;

        }
        else if(action.equals("cmsSign"))
        {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {

                        String alias = args.getString(0);
                        String pData = args.getString(1);

                        Log.v("RSAPlugin", "cmsSign 1");

                        String cmsSing = RSA.cmsSing(alias, pData);

                        Log.v("RSAPlugin", "cmsSign end");

                        /*
                        CertificateAndGostKeyPair cert = null;
                        for (Map.Entry<String, CertificateAndGostKeyPair> entry: mCertificateGostMap.entrySet()){
                            //Log.v("ckaId item", new String(entry.getValue().getCertificate().getCkaId()));
                            if(new String(entry.getValue().getCertificate().getCkaId()).equals(ckaId)){
                                cert = entry.getValue();
                            }
                        }

                        if(cert == null)
                            callbackContext.error("Certificate not found");

                        long hPrivateKey =  cert.getGostKeyPair().getPrivKeyHandle();
                        byte[] data = pData.getBytes();
                        DigestCalculatorProvider dg = new SimpleDigestCalculatorProvider(new SHA256DigestCalculator());
                        RsaContentSigner mRsaContentSigner = new RsaContentSigner(Pkcs11RsaSigner.SignAlgorithm.RSASHA256, session.longValue(), hPrivateKey);


                        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
                        generator.addCertificate(cert.getCertificate().getCertificateHolder());
                        generator.addSignerInfoGenerator(
                                new SignerInfoGeneratorBuilder(dg)
                                        .build(mRsaContentSigner, cert.getCertificate().getCertificateHolder())
                        );
                        CMSTypedData cmsData = new CMSProcessableByteArray(data);
                        CMSSignedData attachedCmsSignature = generator.generate(cmsData, true);
                        */

                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, cmsSing);
                        callbackContext.sendPluginResult(pluginResult);

                    }catch (Exception e){
                        callbackContext.error(e.getMessage());
                    }
                }

            });
            return true;

        }
        else if(action.equals("cmsEncrypt"))
        {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {

                    try {
                        String certs = args.getString(0);
                        String data = args.getString(1);

                        String encryptData = RSA.cmsEncrypt(certs, data);

                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, encryptData);
                        pluginResult.setKeepCallback(true);
                        callbackContext.sendPluginResult(pluginResult);

                    }catch (Exception e){
                        callbackContext.error(e.getMessage());

                    }

                }
            });

            return true;

        }
        else if(action.equals("cmsDecrypt"))
        {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        String alias = args.getString(0);
                        String data = args.getString(1);

                        String decryptData = RSA.cmsDecrypt(alias, data);

                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, decryptData);
                        callbackContext.sendPluginResult(pluginResult);

                    }catch (Exception e){
                        Log.v("Error", e.getMessage());
                        callbackContext.error(e.getMessage());
                    }
                }

            });
            return true;

        }

        callbackContext.error("method not found");
        return false;
    }

}