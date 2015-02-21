//
//  Crypto
//
//  Copyright (c) 2012 Rob Napier
//
//  This code is licensed under the MIT License:
//
//  Permission is hereby granted, free of charge, to any person obtaining a 
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//  
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
//


#import "RNCryptor+Private.h"
#import "Crypto.h"

static const NSUInteger kPreambleSize = 2;

@interface NSData (RNCryptor_ConsistentCompare)

/** Compare two NSData in time proportional to the compared data (otherData)
 *
 * isEqual:-based comparisons stop comparing at the first difference. This can be used by attackers, in some situations,
 * to determine a secret value by considering the time required to compare the values.
 *
 * It is slightly better to call this as [secret rnc_isEqualInConsistentTime:attackersData] rather than the reverse,
 * but it is not a major issue either way. In the first case, the time required is proportional to the attacker's data,
 * which provides the attacker no information about the length of secret. In the second case, the time is proportional
 * to the length of secret, which leaks a small amount of informaiont, but in a way that does not varry in proportion to
 * the attacker's data.
 *
 * @param otherData data to compare
 * @returns YES if values are equal
 */
- (BOOL)rnc_isEqualInConsistentTime:(NSData *)otherData;

@end


@implementation NSData (RNCryptor_ConstantCompare)

- (BOOL)rnc_isEqualInConsistentTime:(NSData *)otherData {
  // The point of this routine is XOR the bytes of each data and accumulate the results with OR.
  // If any bytes are different, then the OR will accumulate some non-0 value.
  
  const uint8_t *myBytes = [self bytes];
  const NSUInteger myLength = [self length];
  const uint8_t *otherBytes = [otherData bytes];
  const NSUInteger otherLength = [otherData length];
  
  uint8_t result = otherLength != myLength;  // Start with 0 (equal) only if our lengths are equal
  
  for (NSUInteger i = 0; i < otherLength; ++i) {
    // Use mod to wrap around ourselves if they are longer than we are.
    // Remember, we already broke equality if our lengths are different.
    result |= myBytes[i % myLength] ^ otherBytes[i];
  }
  
  return result == 0;
}

@end


@interface Crypto ()

@property (nonatomic, readonly) CCCryptorRef cryptor;
@property (nonatomic, readonly) NSMutableData *buffer;

@property (nonatomic, readwrite, strong) NSData *encryptionSalt;
@property (nonatomic, readwrite, strong) NSData *HMACSalt;
@property (nonatomic, readwrite, strong) NSData *IV;
@property (nonatomic, readwrite, assign) BOOL haveWrittenHeader;

@property (nonatomic, readonly, strong) NSMutableData *inData;
@property (nonatomic, readwrite, copy) NSData *encryptionKey;
@property (nonatomic, readwrite, copy) NSData *HMACKey;
@property (nonatomic, readwrite, copy) NSString *password;
@property (nonatomic, readwrite, assign) BOOL hasV1HMAC;

@property (nonatomic, readwrite, assign) RNCryptorSettings settings;
@end



@implementation Crypto
{
  CCHmacContext _HMACContext;
  NSMutableData *__inData;
}

@synthesize cryptor = __cryptor;
@synthesize buffer = __buffer;

@synthesize encryptionSalt = _encryptionSalt;
@synthesize HMACSalt = _HMACSalt;
@synthesize IV = _IV;
@synthesize haveWrittenHeader = _haveWrittenHeader;

@synthesize encryptionKey = _encryptionKey;
@synthesize HMACKey = _HMACKey;
@synthesize password = _password;
@synthesize settings = _settings;


- (Crypto *)initWithOperation:(CCOperation)operation settings:(RNCryptorSettings)settings key:(NSData *)key IV:(NSData *)IV error:(NSError **)error
{
  self = [super init];
  if (self) {
    CCCryptorStatus
    cryptorStatus = CCCryptorCreate(operation,
                                    settings.algorithm,
                                    settings.options,
                                    key.bytes,
                                    key.length,
                                    IV.bytes,
                                    &__cryptor);
    if (cryptorStatus != kCCSuccess || __cryptor == NULL) {
      if (error) {
        *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
      }
      self = nil;
      return nil;
    }
    
    __buffer = [NSMutableData data];
  }
  return self;
}

- (void)dealloc
{
  if (__cryptor) {
    CCCryptorRelease(__cryptor);
  }
}

- (NSData *)addData:(NSData *)data error:(NSError **)error
{
  NSMutableData *buffer = self.buffer;
  [buffer setLength:CCCryptorGetOutputLength(self.cryptor, [data length], true)]; // We'll reuse the buffer in -finish
  
  size_t dataOutMoved;
  CCCryptorStatus
  cryptorStatus = CCCryptorUpdate(self.cryptor,       // cryptor
                                  data.bytes,      // dataIn
                                  data.length,     // dataInLength (verified > 0 above)
                                  buffer.mutableBytes,      // dataOut
                                  buffer.length, // dataOutAvailable
                                  &dataOutMoved);   // dataOutMoved
  
  if (cryptorStatus != kCCSuccess) {
    if (error) {
      *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
    }
    return nil;
  }
  
  return [buffer subdataWithRange:NSMakeRange(0, dataOutMoved)];
}

- (NSData *)finishWithError:(NSError **)error
{
  NSMutableData *buffer = self.buffer;
  size_t dataOutMoved;
  CCCryptorStatus
  cryptorStatus = CCCryptorFinal(self.cryptor,        // cryptor
                                 buffer.mutableBytes,       // dataOut
                                 buffer.length,  // dataOutAvailable
                                 &dataOutMoved);    // dataOutMoved
  if (cryptorStatus != kCCSuccess) {
    if (error) {
      *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
    }
    return nil;
  }
  
  return [buffer subdataWithRange:NSMakeRange(0, dataOutMoved)];
}

+ (NSData *) encryptData: (NSData *) data password: (NSString *) password error: (NSError **) error
{
  return [self encryptData: data withSettings: kRNCryptorAES256Settings password: password error: error];
}


+ (NSData *)encryptData:(NSData *)thePlaintext withSettings:(RNCryptorSettings)theSettings password:(NSString *)aPassword error:(NSError **)anError
{
  Crypto *cryptor = [[self alloc] initWithSettings:theSettings
                                               password:aPassword
                                                handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:thePlaintext direction:@"encrypt" error:anError];
}

+ (NSData *)encryptData:(NSData *)thePlaintext
           withSettings:(RNCryptorSettings)theSettings
               password:(NSString *)aPassword
                     IV:(NSData *)anIV
         encryptionSalt:(NSData *)anEncryptionSalt
               HMACSalt:(NSData *)anHMACSalt
                  error:(NSError **)anError
{
  Crypto *cryptor = [[self alloc] initWithSettings:theSettings
                                               password:aPassword
                                                     IV:anIV
                                         encryptionSalt:anEncryptionSalt
                                               HMACSalt:anHMACSalt
                                                handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:thePlaintext direction:@"encrypt" error:anError];
}

+ (NSData *)encryptData:(NSData *)thePlaintext withSettings:(RNCryptorSettings)theSettings encryptionKey:(NSData *)anEncryptionKey HMACKey:(NSData *)anHMACKey error:(NSError **)anError {
  Crypto *cryptor = [[self alloc] initWithSettings:theSettings
                                          encryptionKey:anEncryptionKey
                                                HMACKey:anHMACKey
                                                handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:thePlaintext direction:@"encrypt" error:anError];
}


+ (NSData *)encryptData:(NSData *)thePlaintext
           withSettings:(RNCryptorSettings)theSettings
          encryptionKey:(NSData *)anEncryptionKey
                HMACKey:(NSData *)anHMACKey
                     IV:(NSData *)anIV
                  error:(NSError **)anError
{
  Crypto *cryptor = [[self alloc] initWithSettings:theSettings
                                          encryptionKey:anEncryptionKey
                                                HMACKey:anHMACKey
                                                     IV:anIV
                                                handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:thePlaintext direction:@"encrypt" error:anError];
}

- (Crypto *)initWithSettings:(RNCryptorSettings)theSettings
                    encryptionKey:(NSData *)anEncryptionKey
                          HMACKey:(NSData *)anHMACKey
                          handler:(RNCryptorHandler)aHandler {
  return [self initWithSettings:kRNCryptorAES256Settings
                  encryptionKey:anEncryptionKey
                        HMACKey:anHMACKey
                             IV:[[self class] randomDataOfLength:theSettings.IVSize]
                        handler:aHandler];
}

- (Crypto *)initWithSettings:(RNCryptorSettings)theSettings
                    encryptionKey:(NSData *)anEncryptionKey
                          HMACKey:(NSData *)anHMACKey
                               IV:(NSData *)anIV
                          handler:(RNCryptorHandler)aHandler
{
  self = [super initWithHandler:aHandler];
  if (self) {
    self.IV = anIV;

    if (anHMACKey) {
      CCHmacInit(&_HMACContext, theSettings.HMACAlgorithm, anHMACKey.bytes, anHMACKey.length);
      self.HMACLength = theSettings.HMACLength;
    }

    NSError *error = nil;
    self.engine = [[Crypto alloc] initWithOperation:kCCEncrypt
                                                    settings:theSettings
                                                         key:anEncryptionKey
                                                          IV:self.IV
                                                       error:&error];
    if (!self.engine) {
      [self cleanupAndNotifyWithError:error];
      self = nil;
      return nil;
    }
  }

  return self;
}

- (Crypto *)initWithSettings:(RNCryptorSettings)theSettings password:(NSString *)aPassword handler:(RNCryptorHandler)aHandler {
    return [self initWithSettings:theSettings
                password:aPassword
                      IV:[[self class] randomDataOfLength:theSettings.IVSize]
          encryptionSalt:[[self class] randomDataOfLength:theSettings.keySettings.saltSize]
                HMACSalt:[[self class] randomDataOfLength:theSettings.HMACKeySettings.saltSize]
                 handler:aHandler];
}


- (Crypto *)initWithSettings:(RNCryptorSettings)theSettings
                         password:(NSString *)aPassword
                               IV:(NSData *)anIV
                   encryptionSalt:(NSData *)anEncryptionSalt
                         HMACSalt:(NSData *)anHMACSalt
                          handler:(RNCryptorHandler)aHandler;
{
  NSParameterAssert(aPassword.length > 0);  // We'll go forward, but this is undefined behavior for RNCryptor
  NSParameterAssert(anIV);
  NSParameterAssert(anEncryptionSalt);
  NSParameterAssert(anHMACSalt);

  NSData *encryptionKey = [[self class] keyForPassword:aPassword salt:anEncryptionSalt settings:theSettings.keySettings];
  NSData *HMACKey = [[self class] keyForPassword:aPassword salt:anHMACSalt settings:theSettings.HMACKeySettings];

  self = [self initWithSettings:theSettings
                  encryptionKey:encryptionKey
                        HMACKey:HMACKey
                             IV:anIV
                        handler:aHandler];
  if (self) {
    self.options |= kRNCryptorOptionHasPassword;
    self.encryptionSalt = anEncryptionSalt;
    self.HMACSalt = anHMACSalt;
  }
  return self;
}

- (NSData *)header
{
  uint8_t header[2] = {kRNCryptorFileVersion, self.options};
  NSMutableData *headerData = [NSMutableData dataWithBytes:header length:sizeof(header)];
  if (self.options & kRNCryptorOptionHasPassword) {
    [headerData appendData:self.encryptionSalt];
    [headerData appendData:self.HMACSalt];
  }
  [headerData appendData:self.IV];
  return headerData;
}

- (void)addEncryptionData:(NSData *)data
{
  if (self.isFinished) {
    return;
  }

  dispatch_async(self.queue, ^{
    if (!self.haveWrittenHeader) {
      NSData *header = [self header];
      [self.outData setData:header];
      if (self.hasHMAC) {
        CCHmacUpdate(&_HMACContext, [header bytes], [header length]);
      }
      self.haveWrittenHeader = YES;
    }

    NSError *error = nil;
    NSData *encryptedData = [self.engine addData:data error:&error];
    if (!encryptedData) {
      [self cleanupAndNotifyWithError:error];
    }
    if (self.hasHMAC) {
      CCHmacUpdate(&_HMACContext, encryptedData.bytes, encryptedData.length);
    }

    [self.outData appendData:encryptedData];

    dispatch_sync(self.responseQueue, ^{
      self.handler(self, self.outData);
    });
    [self.outData setLength:0];
  });
}



- (void)encryptionFinish
{
  if (self.isFinished) {
    return;
  }

  dispatch_async(self.queue, ^{
    NSError *error = nil;
    NSData *encryptedData = [self.engine finishWithError:&error];
    [self.outData appendData:encryptedData];
    if (self.hasHMAC) {
      CCHmacUpdate(&_HMACContext, encryptedData.bytes, encryptedData.length);
      NSMutableData *HMACData = [NSMutableData dataWithLength:self.HMACLength];
      CCHmacFinal(&_HMACContext, [HMACData mutableBytes]);
      [self.outData appendData:HMACData];
    }
    [self cleanupAndNotifyWithError:error];
  });
}

+ (NSData *)decryptData:(NSData *)theCipherText withSettings:(RNCryptorSettings)settings password:(NSString *)aPassword error:(NSError **)anError
{
  Crypto *cryptor = [[self alloc] initWithPassword:aPassword
                                                handler:^(RNCryptor *c, NSData *d) {}];
  cryptor.settings = settings;
  return [self synchronousResultForCryptor:cryptor data:theCipherText direction:@"decrypt" error:anError];
}

+ (NSData *)decryptData:(NSData *)theCipherText withSettings:(RNCryptorSettings)settings encryptionKey:(NSData *)encryptionKey HMACKey:(NSData *)HMACKey error:(NSError **)anError
{
  Crypto *cryptor = [[self alloc] initWithEncryptionKey:encryptionKey
                                                     HMACKey:HMACKey
                                                     handler:^(RNCryptor *c, NSData *d) {}];
  cryptor.settings = settings;
  return [self synchronousResultForCryptor:cryptor data:theCipherText direction:@"decrypt" error:anError];
}

+ (NSData *)decryptData:(NSData *)data password:(NSString *)password error:(NSError **)error
{
  return [self decryptData: data withPassword: password error: error];
}

+ (NSData *)decryptData:(NSData *)theCipherText withPassword:(NSString *)aPassword error:(NSError **)anError
{
  Crypto *cryptor = [[self alloc] initWithPassword:aPassword
                                                handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:theCipherText direction:@"decrypt" error:anError];
}

+ (NSData *)decryptData:(NSData *)theCipherText withEncryptionKey:(NSData *)encryptionKey HMACKey:(NSData *)HMACKey error:(NSError **)anError;
{
  Crypto *cryptor = [[self alloc] initWithEncryptionKey:encryptionKey
                                                     HMACKey:HMACKey
                                                     handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:theCipherText direction:@"decrypt" error:anError];
}

- (Crypto *)initWithEncryptionKey:(NSData *)anEncryptionKey HMACKey:(NSData *)anHMACKey handler:(RNCryptorHandler)aHandler
{
  self = [super initWithHandler:aHandler];
  if (self) {
    _encryptionKey = [anEncryptionKey copy];
    _HMACKey = [anHMACKey copy];
    _settings = kRNCryptorAES256Settings;
  }
  
  return self;
}

- (Crypto *)initWithPassword:(NSString *)aPassword handler:(RNCryptorHandler)aHandler
{
  NSParameterAssert(aPassword != nil);
  
  self = [self initWithEncryptionKey:nil HMACKey:nil handler:aHandler];
  if (self) {
    _password = [aPassword copy];
    _settings = kRNCryptorAES256Settings;
  }
  return self;
}

- (NSMutableData *)inData
{
  if (!__inData) {
    __inData = [NSMutableData data];
  }
  return __inData;
}

- (void)decryptData:(NSData *)data
{
  dispatch_async(self.queue, ^{
    if (self.hasHMAC) {
      CCHmacUpdate(&_HMACContext, data.bytes, data.length);
    }
    
    NSError *error = nil;
    NSData *decryptedData = [self.engine addData:data error:&error];
    
    if (!decryptedData) {
      [self cleanupAndNotifyWithError:error];
      return;
    }
    
    [self.outData appendData:decryptedData];
    
    dispatch_sync(self.responseQueue, ^{
      self.handler(self, self.outData);
    });
    [self.outData setLength:0];
  });
}

- (void)addDecryptionData:(NSData *)theData
{
  if (self.isFinished) {
    return;
  }
  
  [self.inData appendData:theData];
  if (!self.engine) {
    [self consumeHeaderFromData:self.inData];
  }
  if (self.engine) {
    NSUInteger HMACLength = self.HMACLength;
    if (self.inData.length > HMACLength) {
      NSData *data = [self.inData _RNConsumeToIndex:self.inData.length - HMACLength];
      [self decryptData:data];
    }
  }
}

- (BOOL)updateOptionsForPreamble:(NSData *)preamble
{
  const uint8_t *bytes = [preamble bytes];
  
  // See http://robnapier.net/blog/rncryptor-hmac-vulnerability-827 for information on the v1 bad HMAC
#ifdef RNCRYPTOR_ALLOW_V1_BAD_HMAC
  if (bytes[0] == 1) {
    self.options = bytes[1];
    self.hasV1HMAC = YES;
    return YES;
  }
#endif
  
  if (bytes[0] == 2) {
    self.options = bytes[1];
    
    RNCryptorSettings settings = self.settings;
    settings.keySettings.hasV2Password = YES;
    settings.HMACKeySettings.hasV2Password = YES;
    self.settings = settings;
    return YES;
  }
  
  if (bytes[0] == kRNCryptorFileVersion) {
    self.options = bytes[1];
    return YES;
  }
  
  return NO;
}

- (void)consumeHeaderFromData:(NSMutableData *)data
{
  if (data.length < kPreambleSize) {
    return;
  }
  
  if (![self updateOptionsForPreamble:[data subdataWithRange:NSMakeRange(0, kPreambleSize)]]) {
    [self cleanupAndNotifyWithError:[NSError errorWithDomain:kRNCryptorErrorDomain
                                                        code:kRNCryptorUnknownHeader
                                                    userInfo:[NSDictionary dictionaryWithObject:@"Unknown header" /* DNL */
                                                                                         forKey:NSLocalizedDescriptionKey]]];
    return;
  }
  
  NSUInteger headerSize = kPreambleSize + self.settings.IVSize;
  if (self.options & kRNCryptorOptionHasPassword) {
    headerSize += self.settings.keySettings.saltSize + self.settings.HMACKeySettings.saltSize;
  }
  
  if (data.length < headerSize) {
    return;
  }
  
  NSData *header = [data subdataWithRange:NSMakeRange(0, headerSize)];  // We'll need this for the HMAC later
  
  [[data _RNConsumeToIndex:kPreambleSize] mutableCopy]; // Throw away the preamble
  
  NSError *error = nil;
  if (self.options & kRNCryptorOptionHasPassword) {
    NSAssert(!self.encryptionKey && !self.HMACKey, @"Both password and the key (%d) or HMACKey (%d) are set.", self.encryptionKey != nil, self.HMACKey != nil);
    
    NSData *encryptionKeySalt = [data _RNConsumeToIndex:self.settings.keySettings.saltSize];
    NSData *HMACKeySalt = [data _RNConsumeToIndex:self.settings.HMACKeySettings.saltSize];
    self.encryptionKey = [[self class] keyForPassword:self.password salt:encryptionKeySalt settings:self.settings.keySettings];
    self.HMACKey = [[self class] keyForPassword:self.password salt:HMACKeySalt settings:self.settings.HMACKeySettings];
    
    self.password = nil;  // Don't need this anymore.
  }
  
  NSData *IV = [data _RNConsumeToIndex:self.settings.IVSize];
  
  self.engine = [[Crypto alloc] initWithOperation:kCCDecrypt settings:self.settings key:self.encryptionKey IV:IV error:&error];
  self.encryptionKey = nil; // Don't need this anymore
  if (!self.engine) {
    [self cleanupAndNotifyWithError:error];
    return;
  }
  
  if (self.HMACKey) {
    CCHmacInit(&_HMACContext, self.settings.HMACAlgorithm, self.HMACKey.bytes, self.HMACKey.length);
    self.HMACLength = self.settings.HMACLength;
    self.HMACKey = nil; // Don't need this anymore
    
    if (! self.hasV1HMAC) {
      CCHmacUpdate(&_HMACContext, [header bytes], [header length]);
    }
  }
}

- (void)decryptionFinish
{
  if (self.isFinished) {
    return;
  }
  
  dispatch_async(self.queue, ^{
    NSError *error = nil;
    NSData *decryptedData = [self.engine finishWithError:&error];
    
    if (!decryptedData) {
      [self cleanupAndNotifyWithError:error];
      return;
    }
    [self.outData appendData:decryptedData];
    
    if (self.hasHMAC) {
      NSMutableData *HMACData = [NSMutableData dataWithLength:self.HMACLength];
      CCHmacFinal(&_HMACContext, [HMACData mutableBytes]);
      
      if (![HMACData rnc_isEqualInConsistentTime:self.inData]) {
        [self cleanupAndNotifyWithError:[NSError errorWithDomain:kRNCryptorErrorDomain
                                                            code:kRNCryptorHMACMismatch
                                                        userInfo:[NSDictionary dictionaryWithObject:@"HMAC Mismatch" /* DNL */
                                                                                             forKey:NSLocalizedDescriptionKey]]];
        return;
      }
    }
    
    [self cleanupAndNotifyWithError:nil];
  });
}

@end
