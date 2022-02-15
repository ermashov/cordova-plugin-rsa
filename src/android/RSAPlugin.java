package ru.rsa.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import android.util.Log;

public class RSAPlugin extends CordovaPlugin {

    public RSAPlugin() {}

    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) {

        if (action.equals("initialize"))
        {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        String alias = args.getString(0);
                        if (!RSA.isEntryAvailable(alias)) {
                            RSA.createKeyPair(cordova.getActivity().getApplicationContext(), alias);
                        }
                        String certificate = RSA.getCertificate(alias);
                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, certificate);
                        callbackContext.sendPluginResult(pluginResult);
                    } catch (Exception e) {
                        //Log.v("certificate", e.getMessage());
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("getCertificate")) {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        String alias = args.getString(0);
                        String certificate = RSA.getCertificate(alias);
                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, certificate);
                        callbackContext.sendPluginResult(pluginResult);
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("remove")) {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        String alias = args.getString(0);
                      if (RSA.deleteKeyPair(alias)) {
                          PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, "ok");
                          callbackContext.sendPluginResult(pluginResult);
                        }else{
                          PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, "ok");
                          callbackContext.sendPluginResult(pluginResult);
                        }
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if(action.equals("cmsSign")) {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        String alias = args.getString(0);
                        String pData = args.getString(1);

                        String cmsSing = RSA.cmsSing(alias, pData);

                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, cmsSing);
                        callbackContext.sendPluginResult(pluginResult);
                    }catch (Exception e){
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if(action.equals("cmsEncrypt")) {
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
        } else if(action.equals("cmsDecrypt")) {
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
                       // Log.v("Error", e.getMessage());
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