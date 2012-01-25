#import "BraintreeEncryptionTest.h"
#import "NSData+Base64.h"
#import "BraintreeDecrypt.h"
#import "TestRSAKeys.h"


@implementation BraintreeEncryptionTest

-(void) testInitProperties {
  BraintreeEncryption * crypto   = [[BraintreeEncryption alloc] initWithPublicKey:@"cryptkeeper"];
  STAssertEqualObjects([crypto publicKey], @"cryptkeeper", @"sets the publicKey property");
}

-(void) testEncryptStartsWithPrefix {
  BraintreeEncryption * crypto   = [[BraintreeEncryption alloc] initWithPublicKey: publicKey];
  NSString  * encryptedData = [crypto encryptData: [@"test data" dataUsingEncoding:NSUTF8StringEncoding]];

  STAssertTrue([encryptedData hasPrefix: @"$bt3|ios"], @"");
}

-(void) testEncryptWithString {
  BraintreeEncryption * crypto = [[BraintreeEncryption alloc] initWithPublicKey: publicKey];

  NSString * encryptedString = [crypto encryptString:@"test data"];
  STAssertTrue([encryptedString hasPrefix: @"$bt3|ios"], @"");
}

-(void) testRoundTrip {
  BraintreeEncryption * crypto = [[BraintreeEncryption alloc] initWithPublicKey: publicKey];
  NSString * encryptedString = [crypto encryptString: @"test data"];
  NSArray * aesInfo = [[encryptedString stringByReplacingOccurrencesOfString: [crypto tokenWithVersion] withString:@""]
                       componentsSeparatedByString:@"$"];

  NSString * aesKey = [BraintreeDecrypt decryptWithKey:[BraintreeDecrypt getPrivateKeyRef: privateKey]
                                                  Data: [NSData dataWithBase64EncodedString:[aesInfo objectAtIndex:0]]];

  NSData * decryptedData = [BraintreeDecrypt decryptAES: [NSData dataWithBase64EncodedString:[aesInfo objectAtIndex:1]]
                                                withKey:aesKey];

  STAssertEqualObjects(decryptedData, [@"test data" dataUsingEncoding:NSUTF8StringEncoding], @"round trip!");
}

@end
