#import "BraintreeAESTest.h"
#import "BraintreeAES.h"
#import "NSData+Base64.h"
#import "BraintreeDecrypt.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation BraintreeAESTest

-(void) testAESEncryptionWithKeyAndIv {
  NSData   * ivData          = [NSData dataWithBase64EncodedString:@"AAAAAQAAAAIAAAADAAAABA=="];
  NSString * key             = @"iz5DQzn/XpwXvZ7wY3OGQRVBZTFeVMrEIUljWrIr2Pg=";

  NSData   * plainData       = [@"test data" dataUsingEncoding:NSUTF8StringEncoding];
  NSString * encryptedString = [BraintreeAES encrypt: plainData withKey: key Iv: ivData];
  NSData   * encryptedData   = [NSData dataWithBase64EncodedString:encryptedString];

  STAssertEqualObjects(encryptedString, @"AAAAAQAAAAIAAAADAAAABJcSo857BMv+cJtJfpF5Pak=", @"matches pre-generated AC");
  STAssertEqualObjects([BraintreeDecrypt decryptAES: encryptedData withKey: key], plainData, @"round trip success");
}

-(void) testBTCryptoAES256WithoutIv {
  NSString * key = @"iz5DQzn/XpwXvZ7wY3OGQRVBZTFeVMrEIUljWrIr2Pg=";

  NSData   * plainData       = [@"test data" dataUsingEncoding: NSUTF8StringEncoding];
  NSString * encryptedString = [BraintreeAES encrypt: plainData withKey: key];

  STAssertTrue([encryptedString length] == 44, @"matches expected length");
}

@end
