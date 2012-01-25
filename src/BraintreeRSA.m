#import "BraintreeRSA.h"
#import "SecKeyWrapper.h"
#import "NSData+Base64.h"

#include <CommonCrypto/CommonCryptor.h>
#include <Security/Security.h>

@implementation BraintreeRSA

@synthesize publicKey;
@synthesize publicKeyRef;
@synthesize applicationTag;

-(id)init {
    self = [super init];
    return self;
}

-(id) initWithKeyRef: (SecKeyRef) key {
  self = [super init];
  publicKeyRef = key;
  applicationTag = @"com.braintree.public_encryption_key";
  return self;
}

-(id) initWithKey: (NSString*) key {
  self = [super init];
  publicKey = key;
  applicationTag = @"com.braintree.public_encryption_key";
  return self;
}

-(NSData*) encrypt:(NSString*) data {
  uint8_t* plainText = (uint8_t *)[[data dataUsingEncoding:NSUTF8StringEncoding] bytes];

  SecKeyRef keyRef = [self getKeychainPublicKeyRef];

  size_t cipherTextSize = 256;
  uint8_t *cipherTextBuf = NULL;

  cipherTextBuf = malloc(cipherTextSize);
  memset(cipherTextBuf, 0, cipherTextSize);

  OSStatus result = SecKeyEncrypt(keyRef, kCCOptionPKCS7Padding,
                                  plainText, [data length],
                                  cipherTextBuf, &cipherTextSize);

  if(result != noErr)
    NSLog(@"Secure Key Encryption Failed With Error: %ld", result);


  return [[[NSData alloc] initWithBytes: cipherTextBuf length:cipherTextSize] autorelease];
}

-(SecKeyRef) getKeychainPublicKeyRef {
  if(publicKeyRef != NULL)
    return publicKeyRef;

  SecKeyWrapper * wrapper = [[[SecKeyWrapper alloc] init] autorelease];
  NSData * publicKeyData  = [NSData dataWithBase64EncodedString: publicKey];

  return [wrapper addPeerPublicKey:applicationTag keyBits: publicKeyData];
}

-(void) dealloc {
  publicKeyRef = NULL;
  [publicKey release];
  [applicationTag release];
  [super dealloc];
}

@end
