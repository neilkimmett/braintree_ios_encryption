#import <Foundation/Foundation.h>

@interface BraintreeRandom : NSObject

+ (NSData*) randomWordsAsData:(int) count;
+ (uint8_t*) randomWords:(int) count;

@end
