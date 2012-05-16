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

-(void) testEncryptWithStringFormat {
  BraintreeEncryption * crypto = [[BraintreeEncryption alloc] initWithPublicKey: publicKey];
  NSString *encryptedString = [crypto encryptString: @"test data"];
  NSArray *aesInfo = [[encryptedString stringByReplacingOccurrencesOfString: [crypto tokenWithVersion] withString:@""]
                       componentsSeparatedByString:@"$"];

  NSString *aesKey = [aesInfo objectAtIndex:1];
  NSString *encryptedData = [aesInfo objectAtIndex:2];
  NSString *version = [VERSION stringByReplacingOccurrencesOfString:@"." withString: @"_"];

  NSString *expectedString = [NSString stringWithFormat:@"$bt3|ios_%@$%@$%@", version, aesKey, encryptedData, nil];
  STAssertTrue([encryptedString isEqualToString: expectedString], @"");
}

-(void) testRoundTrip {
  BraintreeEncryption * crypto = [[BraintreeEncryption alloc] initWithPublicKey: publicKey];
  NSString * encryptedString = [crypto encryptString: @"test data"];
  NSArray * aesInfo = [[encryptedString stringByReplacingOccurrencesOfString: [crypto tokenWithVersion] withString:@""]
                       componentsSeparatedByString:@"$"];

  NSString * aesKey = [BraintreeDecrypt decryptWithKey:[BraintreeDecrypt getPrivateKeyRef: privateKey]
                                                  Data: [NSData dataWithBase64EncodedString:[aesInfo objectAtIndex:1]]];

  NSData * decryptedData = [BraintreeDecrypt decryptAES: [NSData dataWithBase64EncodedString:[aesInfo objectAtIndex:2]]
                                                withKey:aesKey];

  STAssertEqualObjects(decryptedData, [@"test data" dataUsingEncoding:NSUTF8StringEncoding], @"round trip!");
}

@end
