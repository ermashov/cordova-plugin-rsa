package ru.rsa.plugins;


public class RSAPlugin extends CordovaPlugin {


    public RSAPlugin() {}

    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) {

        Context context = this.cordova.getActivity().getApplicationContext();

        if (action.equals("getPublicKey"))
        {

            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {


                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, new String("getPublicKey"));
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

                        String ckaId = args.getString(0);
                        String pData = args.getString(1);



                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, new String("cmsSign"));
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
                        String arg1 = args.getString(0);
                        String arg2 = args.getString(1);

                        String[] arCerts = certs.split(",");


                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, new String("cmsEncrypt"));
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
                        String arg1 = args.getString(0);
                        String arg2 = args.getString(1);



                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, new String("cmsDecrypt"));
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