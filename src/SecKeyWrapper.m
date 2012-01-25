#import "SecKeyWrapper.h"
#import <Security/Security.h>

@implementation SecKeyWrapper

#if DEBUG
	#define LOGGING_FACILITY(X, Y)	\
					NSAssert(X, Y);

	#define LOGGING_FACILITY1(X, Y, Z)	\
					NSAssert1(X, Y, Z);
#else
	#define LOGGING_FACILITY(X, Y)	\
				if (!(X)) {			\
					NSLog(Y);		\
				}

	#define LOGGING_FACILITY1(X, Y, Z)	\
				if (!(X)) {				\
					NSLog(Y, Z);		\
				}
#endif

- (SecKeyRef)addPeerPublicKey:(NSString *)peerName keyBits:(NSData *)publicKey {
  [self removePeerPublicKey:peerName];

	OSStatus sanityCheck = noErr;
	SecKeyRef peerKeyRef = NULL;

	LOGGING_FACILITY( peerName != nil, @"Peer name parameter is nil." );
	LOGGING_FACILITY( publicKey != nil, @"Public key parameter is nil." );

	NSData * peerTag = [[NSData alloc] initWithBytes:(const void *)[peerName UTF8String] length:[peerName length]];
	NSMutableDictionary * peerPublicKeyAttr = [[NSMutableDictionary alloc] init];

	[peerPublicKeyAttr setObject:(id)kSecClassKey       forKey:(id)kSecClass];
	[peerPublicKeyAttr setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
	[peerPublicKeyAttr setObject:peerTag                forKey:(id)kSecAttrApplicationTag];
	[peerPublicKeyAttr setObject:publicKey              forKey:(id)kSecValueData];
	[peerPublicKeyAttr setObject:(id)kCFBooleanTrue     forKey:(id)kSecReturnRef];

	sanityCheck = SecItemAdd((CFDictionaryRef) peerPublicKeyAttr, (CFTypeRef *)&peerKeyRef);

	LOGGING_FACILITY1( sanityCheck == noErr, @"Problem adding the public key, OSStatus == %ld.", sanityCheck );

  [peerPublicKeyAttr removeObjectForKey:(id)kSecValueData];
  sanityCheck = SecItemCopyMatching((CFDictionaryRef) peerPublicKeyAttr, (CFTypeRef *)&peerKeyRef);

	LOGGING_FACILITY1( sanityCheck == noErr && peerKeyRef != NULL, @"Problem acquiring reference to the public key, OSStatus == %ld.", sanityCheck );

	[peerTag release];
	[peerPublicKeyAttr release];
	return peerKeyRef;
}

- (void)removePeerPublicKey:(NSString *)peerName {
	OSStatus sanityCheck = noErr;

	LOGGING_FACILITY( peerName != nil, @"Peer name parameter is nil." );

	NSData * peerTag = [[NSData alloc] initWithBytes:(const void *)[peerName UTF8String] length:[peerName length]];
	NSMutableDictionary * peerPublicKeyAttr = [[NSMutableDictionary alloc] init];

	[peerPublicKeyAttr setObject:(id)kSecClassKey forKey:(id)kSecClass];
	[peerPublicKeyAttr setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
	[peerPublicKeyAttr setObject:peerTag forKey:(id)kSecAttrApplicationTag];

	sanityCheck = SecItemDelete((CFDictionaryRef) peerPublicKeyAttr);

	LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Problem deleting the peer public key from keychain, OSStatus == %ld.", sanityCheck );

	[peerTag release];
	[peerPublicKeyAttr release];
}

@end
