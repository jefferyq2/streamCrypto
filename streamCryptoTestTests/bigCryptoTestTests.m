//
//  bigCryptoTestTests.m
//  bigCryptoTestTests
//
//  Created by Dmitry Rybakov on 2018-02-07.
//  Copyright © 2018 Dmitry Rybakov. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <CommonCrypto/CommonCrypto.h>

#import "QCCRSASmallCryptor.h"
#import "QCCAESPadBigCryptor.h"

@implementation NSString(Hex)

-(nullable NSData *)optionalDataWithHexString {
    NSMutableData *     result;
    NSUInteger          cursor;
    NSUInteger          limit;

    result = nil;
    cursor = 0;
    limit = self.length;
    if ((limit % 2) == 0) {
        result = [[NSMutableData alloc] init];

        while (cursor != limit) {
            unsigned int    thisUInt;
            uint8_t         thisByte;

            if ( sscanf([self substringWithRange:NSMakeRange(cursor, 2)].UTF8String,
                        "%x", &thisUInt) != 1 ) {
                result = nil;
                break;
            }
            thisByte = (uint8_t) thisUInt;
            [result appendBytes:&thisByte length:sizeof(thisByte)];
            cursor += 2;
        }
    }

    return result;
}

-(NSData *)dataWithHexString {
    NSData *    result;

    result = [self optionalDataWithHexString];
    if (result == nil) {
        abort();
    }
    return result;
}
@end

@interface bigCryptoTestTests : XCTestCase

@property (nonatomic, strong, readwrite, nullable) SecKeyRef publicKey __attribute__ (( NSObject ));
@property (nonatomic, strong, readwrite, nullable) SecKeyRef privateKey __attribute__ (( NSObject ));

@end

@implementation bigCryptoTestTests

- (void)setUpPhone {
    OSStatus            err;
    NSData *            certData;
    SecCertificateRef   cert;
    SecPolicyRef        policy;
    SecTrustRef         trust;
    SecTrustResultType  trustResult;

    // public key

    certData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(certData != nil);

    cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef) certData);
    assert(cert != NULL);

    policy = SecPolicyCreateBasicX509();

    err = SecTrustCreateWithCertificates(cert, policy, &trust);
    assert(err == errSecSuccess);

    err = SecTrustEvaluate(trust, &trustResult);
    assert(err == errSecSuccess);

    self->_publicKey = SecTrustCopyPublicKey(trust);
    assert(self->_publicKey != NULL);

    CFRelease(policy);
    CFRelease(cert);

    // private key

    NSData *            pkcs12Data;
    CFArrayRef          imported;
    NSDictionary *      importedItem;
    SecIdentityRef      identity;

    pkcs12Data = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"private" withExtension:@"p12"]];
    assert(pkcs12Data != nil);

    err = SecPKCS12Import((__bridge CFDataRef) pkcs12Data, (__bridge CFDictionaryRef) @{
                                                                                        (__bridge NSString *) kSecImportExportPassphrase: @"test"
                                                                                        }, &imported);
    assert(err == errSecSuccess);
    assert(CFArrayGetCount(imported) == 1);
    importedItem = (__bridge NSDictionary *) CFArrayGetValueAtIndex(imported, 0);
    assert([importedItem isKindOfClass:[NSDictionary class]]);
    identity = (__bridge SecIdentityRef) importedItem[(__bridge NSString *) kSecImportItemIdentity];
    assert(identity != NULL);

    err = SecIdentityCopyPrivateKey(identity, &self->_privateKey);
    assert(err == errSecSuccess);
    assert(self->_privateKey != NULL);

    CFRelease(imported);
}

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    [self setUpPhone];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testAES128PadBigCBCEncryption {
    NSData *                inputData;
    NSInputStream *         inputStream;
    NSOutputStream *        outputStream;
    NSData *                keyData;
    NSData *                ivData;
    QCCAESPadBigCryptor *   op;
    NSData *                expectedOutputData;

    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-332" withExtension:@"dat"]];
    assert(inputData != nil);

    inputStream = [NSInputStream inputStreamWithData:inputData];
    assert(inputStream != nil);

    outputStream = [NSOutputStream outputStreamToMemory];
    assert(outputStream != nil);

    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-332" withExtension:@"dat"]];
    assert(expectedOutputData != nil);

    keyData = [@"0C1032520302EC8537A4A82C4EF7579D" dataWithHexString];
    assert(keyData != nil);

    ivData = [@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7" dataWithHexString];
    assert(ivData != nil);

    op = [[QCCAESPadBigCryptor alloc] initToEncryptInputStream:inputStream toOutputStream:outputStream keyData:keyData];
    op.ivData = ivData;
    // synchronouslyRunOperation
    [op main];
    XCTAssertNil(op.error);
    XCTAssertEqualObjects(expectedOutputData, [outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey]);
}

// When you encrypt with padding you can't test a fixed encryption because the padding
// adds some randomness so that no two encryptions are the same.  Thus, we can only test
// the round trip case (-testRSASmallCryptor) and the decrypt case (-testRSADecryptPKCS1
// and -testRSADecryptOAEP).

- (void)testRSASmallCryptor {
    // Should have Unified Crypto otherwise we cannot proceed
    if (&SecKeyCreateEncryptedData == NULL) { return; }

    NSData *                    fileData;
    QCCRSASmallCryptor *        op;

    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-32" withExtension:@"dat"]];
    assert(fileData != nil);

    op = [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:fileData key:self.publicKey];
    [op main];
    XCTAssertNil(op.error);

    if (op.smallOutputData != nil) {
        op = [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:op.smallOutputData key:self.privateKey];
        [op main];
        XCTAssertNil(op.error);

        XCTAssertEqualObjects(fileData, op.smallOutputData);
    }
}

- (void)testRSADecryptPKCS1 {
    // Should have Unified Crypto otherwise we cannot proceed
    if (&SecKeyCreateEncryptedData == NULL) { return; }

    NSData *                    fileData;
    QCCRSASmallCryptor *        op;
    NSData *                    cyphertext32Data;

    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-32" withExtension:@"dat"]];
    assert(fileData != nil);

    // This is the "plaintext-32.dat" data encrypted with the public key using the
    // following OpenSSL command:
    //
    // $ openssl rsautl -encrypt -pkcs -pubin -inkey TestData/public.pem -in TestData/plaintext-32.dat

    cyphertext32Data = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-pkcs1-32" withExtension:@"dat"]];
    assert(cyphertext32Data != nil);

    op = [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:cyphertext32Data key:self.privateKey];
    [op main];
    XCTAssertNil(op.error);

    XCTAssertEqualObjects(fileData, op.smallOutputData);
}

@end
