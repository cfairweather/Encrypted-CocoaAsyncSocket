//
//  EGCDAsyncSocket.m
//  ConnectTest
//
//  Created by Cris Fairweather on 3/3/13.
//
//

#import "EGCDAsyncSocket.h"
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonCrypto.h>

@interface EGCDAsyncSocket (){
    BOOL socketIsEncrypted;
    NSData *cryptoKey;
    int encryptionStrength;
    id eDelegate;
}
@end

@implementation EGCDAsyncSocket


//Delegate override

-(id)init{
    self = [super init];
    if(self)
    {
        [super setDelegate:self];
    }
    return self;
}

-(id)initWithDelegate:(id)aDelegate delegateQueue:(dispatch_queue_t)dq{
    self = [super initWithDelegate:self delegateQueue:dq];
    if(self){
        eDelegate = aDelegate;
    }
    return self;
}
-(id)initWithDelegate:(id)aDelegate delegateQueue:(dispatch_queue_t)dq socketQueue:(dispatch_queue_t)sq{
    self = [super initWithDelegate:self delegateQueue:dq socketQueue:sq];
    if(self){
        eDelegate = aDelegate;
    }
    return self;
}

-(void)setDelegate:(id)delegate{
    eDelegate = delegate;
}

-(void)setDelegate:(id)delegate delegateQueue:(dispatch_queue_t)delegateQueue{
    eDelegate = delegate;
    [super setDelegate:self delegateQueue:delegateQueue];
}


//Implement protocol!
- (dispatch_queue_t)newSocketQueueForConnectionFromAddress:(NSData *)address onSocket:(GCDAsyncSocket *)sock{
    if([eDelegate respondsToSelector:@selector(newSocketQueueForConnectionFromAddress:onSocket:)])
        return [eDelegate newSocketQueueForConnectionFromAddress:address onSocket:sock];
    return NULL;
}

- (void)socket:(GCDAsyncSocket *)sock didAcceptNewSocket:(GCDAsyncSocket *)newSocket{
    if([eDelegate respondsToSelector:@selector(socket:didAcceptNewSocket:)]){
        [eDelegate socket:sock didAcceptNewSocket:newSocket];
    }
}

- (void)socket:(GCDAsyncSocket *)sock didConnectToHost:(NSString *)host port:(uint16_t)port{
    if([eDelegate respondsToSelector:@selector(socket:didConnectToHost:port:)]){
        [eDelegate socket:sock didConnectToHost:host port:port];
    }
    
}

- (void)socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag{
    if ([eDelegate respondsToSelector:@selector(socket:didReadData:withTag:)]) {
        if(socketIsEncrypted)
            data = [CryptoHelper AESDecryptWithKey:cryptoKey strength:encryptionStrength andData:data];
        
        [eDelegate socket:sock didReadData:data withTag:tag];
    }
}

- (void)socket:(GCDAsyncSocket *)sock didReadPartialDataOfLength:(NSUInteger)partialLength tag:(long)tag{
    if ([eDelegate respondsToSelector:@selector(socket:didReadPartialDataOfLength:tag:)]) {
        [eDelegate socket:sock didReadPartialDataOfLength:partialLength tag:tag];
    }
}

- (void)socket:(GCDAsyncSocket *)sock didWriteDataWithTag:(long)tag{
    if ([eDelegate respondsToSelector:@selector(socket:didWriteDataWithTag:)]) {
        [eDelegate socket:sock didWriteDataWithTag:tag];
    }
}

- (void)socket:(GCDAsyncSocket *)sock didWritePartialDataOfLength:(NSUInteger)partialLength tag:(long)tag;{
    
    if ([eDelegate respondsToSelector:@selector(socket:didWritePartialDataOfLength:tag:)]) {
        [eDelegate socket:sock didWritePartialDataOfLength:partialLength tag:tag];
    }
}

- (NSTimeInterval)socket:(GCDAsyncSocket *)sock shouldTimeoutReadWithTag:(long)tag elapsed:(NSTimeInterval)elapsed bytesDone:(NSUInteger)length{
    if([eDelegate respondsToSelector:@selector(socket:shouldTimeoutReadWithTag:elapsed:bytesDone:)]){
        return [eDelegate socket:sock shouldTimeoutReadWithTag:tag elapsed:elapsed bytesDone:length];
    }
    return NULL;
}

- (NSTimeInterval)socket:(GCDAsyncSocket *)sock shouldTimeoutWriteWithTag:(long)tag elapsed:(NSTimeInterval)elapsed bytesDone:(NSUInteger)length{
    if ([eDelegate respondsToSelector:@selector(socket:shouldTimeoutWriteWithTag:elapsed:bytesDone:)]) {
        return [eDelegate socket:sock shouldTimeoutWriteWithTag:tag elapsed:elapsed bytesDone:length];
    }
    return NULL;
}

- (void)socketDidCloseReadStream:(GCDAsyncSocket *)sock{
    if ([eDelegate respondsToSelector:@selector(socketDidCloseReadStream:)]) {
        [eDelegate socketDidCloseReadStream:sock];
    }
}

- (void)socketDidDisconnect:(GCDAsyncSocket *)sock withError:(NSError *)err{
    if ([eDelegate respondsToSelector:@selector(socketDidDisconnect:withError:)]) {
        [eDelegate socketDidDisconnect:sock withError:err];
    }
}

- (void)socketDidSecure:(GCDAsyncSocket *)sock{
    if ([eDelegate respondsToSelector:@selector(socketDidSecure:)]) {
        [eDelegate socketDidSecure:sock];
    }
}



//Encryptions
-(BOOL)startAESWithStrength:(BOOL)is256 key:(NSData*)cryptoKey{
    encryptionStrength = EGCDAsyncSocket_AES128;
    if(is256)
        encryptionStrength = EGCDAsyncSocket_AES256;
    
    return YES;
}

-(BOOL)startAESWithStrength:(BOOL)is256 password:(NSString*)password salt:(NSString*)salt iterations:(int)iterations{
    NSData* key = [CryptoHelper generateKeyWithPIN:password andSalt:salt strength:(is256)?EGCDAsyncSocket_AES256:EGCDAsyncSocket_AES128 iterations:iterations];
    return [self startAESWithStrength:is256 key:key];
}

//Uses application bundle name for salt and defaults iterations to 2000;
-(BOOL)startAESWithStrength:(BOOL)is256 password:(NSString*)password{
    return [self startAESWithStrength:is256 password:password salt:[NSBundle mainBundle].bundleIdentifier iterations:2000];
}

-(BOOL)stopAES{
    socketIsEncrypted = NO;
    return YES;
}

-(BOOL)isEncrypted{
    return socketIsEncrypted;
}




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark GCDAsync Overrides
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

-(void)writeData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag{
    //Crypto stuff
    if(socketIsEncrypted)
        data = [CryptoHelper AESEncryptWithKey:cryptoKey strength:encryptionStrength andData:data];
    [super writeData:data withTimeout:timeout tag:tag];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Reading overrides
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


- (void)readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag
{
    if(socketIsEncrypted)
        data = [CryptoHelper AESEncryptWithKey:cryptoKey strength:encryptionStrength andData:data];
    [super readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag];
}

- (void)readDataToData:(NSData *)data
           withTimeout:(NSTimeInterval)timeout
                buffer:(NSMutableData *)buffer
          bufferOffset:(NSUInteger)offset
                   tag:(long)tag
{
    
    if(socketIsEncrypted)
        data = [CryptoHelper AESEncryptWithKey:cryptoKey strength:encryptionStrength andData:data];
    [super readDataToData:(NSData *)data
              withTimeout:(NSTimeInterval)timeout
                   buffer:(NSMutableData *)buffer
             bufferOffset:(NSUInteger)offset
                      tag:(long)tag];
}

- (void)readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout maxLength:(NSUInteger)length tag:(long)tag
{
    if(socketIsEncrypted)
        data = [CryptoHelper AESEncryptWithKey:cryptoKey strength:encryptionStrength andData:data];
    [super readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout maxLength:(NSUInteger)length tag:(long)tag];
}

- (void)readDataToData:(NSData *)data
           withTimeout:(NSTimeInterval)timeout
                buffer:(NSMutableData *)buffer
          bufferOffset:(NSUInteger)offset
             maxLength:(NSUInteger)maxLength
                   tag:(long)tag
{
    if(socketIsEncrypted)
        data = [CryptoHelper AESEncryptWithKey:cryptoKey strength:encryptionStrength andData:data];
    [super readDataToData:(NSData *)data
              withTimeout:(NSTimeInterval)timeout
                   buffer:(NSMutableData *)buffer
             bufferOffset:(NSUInteger)offset
                maxLength:(NSUInteger)maxLength
                      tag:(long)tag];
}

@end



@implementation CryptoHelper


+(NSData*)generateKeyWithPIN:(NSString*)pin andSalt:(NSString*)salt strength:(int)strength iterations:(int)iterations{
    assert(strength == EGCDAsyncSocket_AES128 || strength == EGCDAsyncSocket_AES256);
    
    NSData* myPassData = [pin dataUsingEncoding:NSUTF8StringEncoding];
    NSData* dataSalt = [salt dataUsingEncoding:NSStringEncodingConversionAllowLossy];
    
    unsigned char key[strength];
    CCKeyDerivationPBKDF(kCCPBKDF2, myPassData.bytes, myPassData.length, dataSalt.bytes, salt.length, kCCPRFHmacAlgSHA256, iterations, key, strength);
    return [NSData dataWithBytes:&key length:strength];
}


+(NSData*)AESEncryptWithKey:(NSData*)key strength:(int)strength andData:(NSData*)data {
    assert(strength == EGCDAsyncSocket_AES128 || strength == EGCDAsyncSocket_AES256);
    
    CCOptions ccOptions = kCCOptionECBMode;
    if(EGCDAsyncSocket_PKCS7_PADDING)
        ccOptions = kCCOptionECBMode | kCCOptionPKCS7Padding;
    
    size_t keySize = 0;
    
    if(strength == EGCDAsyncSocket_AES128){
        keySize = kCCKeySizeAES128;
    }else{//EGCDAsyncSocket_AES256
        keySize = kCCKeySizeAES256;
    }
    
    char keyPtr[keySize + 1]; // room for terminator
    
    NSUInteger dataLength = data.length;
    
    size_t bufferSize           = dataLength + kCCBlockSizeAES128;
    void* buffer                = malloc(bufferSize);
    
    unsigned char *bytesForEncryption = malloc( dataLength * sizeof(unsigned char) );
    
    // Get the data
    [data getBytes:bytesForEncryption length:dataLength];
    
    size_t numBytesEncrypted    = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, ccOptions,
                                          keyPtr, keySize,
                                          NULL /* initialization vector (optional) */,
                                          bytesForEncryption, dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
    
    free(bytesForEncryption);
    if (cryptStatus == kCCSuccess)
    {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    return nil;
}

+(NSData*)AESDecryptWithKey:(NSData*)key strength:(int)strength andData:(NSData*)data {
    assert(strength == EGCDAsyncSocket_AES128 || strength == EGCDAsyncSocket_AES256);
    
    CCOptions ccOptions = kCCOptionECBMode;
    if(EGCDAsyncSocket_PKCS7_PADDING)
        ccOptions = kCCOptionECBMode | kCCOptionPKCS7Padding;
    
    size_t keySize = 0;
    
    if(strength == EGCDAsyncSocket_AES128){
        keySize = kCCKeySizeAES128;
    }else{//EGCDAsyncSocket_AES256
        keySize = kCCKeySizeAES256;
    }
    
    char keyPtr[keySize + 1]; // room for terminator
    
    [key getBytes:&keyPtr];
    
    NSUInteger dataLength = data.length;
    
    size_t bufferSize           = dataLength + kCCBlockSizeAES128;
    void* buffer                = malloc(bufferSize);
    
    unsigned char *bytesForDecryption = malloc( dataLength * sizeof(unsigned char) );
    
    // Get the data
    [data getBytes:bytesForDecryption length:dataLength];
    
    size_t numBytesDecrypted    = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, ccOptions, keyPtr,     keySize,
                                          NULL /* initialization vector (optional) */,
                                          bytesForDecryption, dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    
    free(bytesForDecryption);
    if (cryptStatus == kCCSuccess)
    {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    return nil;
}



@end