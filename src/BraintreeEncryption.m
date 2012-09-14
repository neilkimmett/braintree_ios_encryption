#import "BraintreeEncryption.h"
#import "BraintreeAES.h"
#import "BraintreeRSA.h"
#import "NSData+Base64.h"
#import "BraintreeRandom.h"

@implementation BraintreeEncryption

@synthesize publicKey;
@synthesize applicationTag;

NSString * const VERSION = @"1.0.1";

- (id)init {
  self = [super init];
  return self;
}

- (id)initWithPublicKey: (NSString *) key {
  self = [super init];

  publicKey = key;

  return self;
}

-(NSString*) encryptData: (NSData*) data {
  NSString * randomKey = [[BraintreeRandom randomWordsAsData:8] base64Encoding];
  BraintreeRSA * rsa = [[BraintreeRSA alloc] initWithKey:publicKey];
  NSString * encryptedKey = [[rsa encrypt: randomKey] base64Encoding];

  NSString * encryptedData = [BraintreeAES encrypt:data withKey:randomKey];

  return [[[[[self tokenWithVersion]
           stringByAppendingString: @"$"]
           stringByAppendingString: encryptedKey]
           stringByAppendingString: @"$"]
           stringByAppendingString: encryptedData];
}

-(NSString*) encryptString: (NSString*) input {
  NSData * data = [input dataUsingEncoding:NSUTF8StringEncoding];
  return [self encryptData: data];
}

-(NSString*) tokenWithVersion {
  NSString * formattedVersion = [VERSION stringByReplacingOccurrencesOfString:@"." withString: @"_"];

  return [NSString stringWithFormat: @"$bt3|ios_%@", formattedVersion];

}

@end
