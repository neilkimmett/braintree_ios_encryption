#import <Foundation/Foundation.h>

@interface BraintreeDecrypt : NSObject
+ (NSData*)decryptAES:(NSData*) data withKey:(NSString*)key;
+ (SecKeyRef) getPrivateKeyRef:(NSString*) privateKey;
+ (NSString *) decryptWithKey:(SecKeyRef)privateKey Data:(NSData*)encryptedData;

@end
