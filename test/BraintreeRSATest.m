#import "BraintreeRSATest.h"
#import "BraintreeRSA.h"
#import "BraintreeDecrypt.h"
#import "TestRSAKeys.h"

@implementation BraintreeRSATest

- (void) testSetsPropertiesOnInstance {
  BraintreeRSA * rsa   = [[BraintreeRSA alloc] initWithKey:publicKey];
  STAssertEqualObjects([rsa publicKey], publicKey, @"sets the public key");
}

- (void) testRoundTripWithExistingKey {
  NSString * plainText = @"test data";
  BraintreeRSA * rsa   = [[BraintreeRSA alloc] initWithKey:publicKey];
  NSData * encryptedData = [rsa encrypt: plainText];

  NSString * plainStr = [BraintreeDecrypt decryptWithKey:(SecKeyRef)[BraintreeDecrypt getPrivateKeyRef:privateKey] Data:encryptedData];

  [rsa release];

  STAssertEqualObjects(plainStr, @"test data", @"success!");
}

@end
