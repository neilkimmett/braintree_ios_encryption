#import <Foundation/Foundation.h>

@interface BraintreeAES : NSObject

+ (NSString*) encrypt:(NSData*) data withKey:(NSString*) key;
+ (NSString*) encrypt:(NSData*) data withKey:(NSString*) key Iv:(NSData*) iv;

@end
