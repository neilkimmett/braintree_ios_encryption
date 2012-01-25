#import "BraintreeRandomTest.h"
#import "BraintreeRandom.h"
#import "NSData+Base64.h"

@implementation BraintreeRandomTest
-(void) testRandomIsRandom {
  NSData * one = [BraintreeRandom randomWordsAsData:4];
  NSData * two = [BraintreeRandom randomWordsAsData:4];

  STAssertNotNil(one, @"not null!");
  STAssertTrue(one != two, @"");
}

-(void) testRandomLength {
  NSString * randoms = [[BraintreeRandom randomWordsAsData:4] base64Encoding];
  STAssertTrue([randoms length] == 24, @"uses the length argument correctly");
}

@end
