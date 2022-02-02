
#import <Cordova/CDV.h>

@implementation RSAPlugin

- (void)init:(CDVInvokedUrlCommand*)command
{
	[self.commandDelegate runInBackground:^{
		CDVPluginResult* pluginResult = nil;

		NSString* hex = [NSString "test"];
		if (hex != nil && [hex length] > 0) {
			pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:hex];
		} else {
			pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
		}
		[self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
	}];
}
@end
