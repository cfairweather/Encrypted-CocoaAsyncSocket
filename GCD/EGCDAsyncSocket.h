//
//  EGCDAsyncSocket.h
//  ConnectTest
//
//  Created by Cris Fairweather on 3/3/13.
//
//

#import "GCDAsyncSocket.h"

#define EGCDAsyncSocket_AES256 32
#define EGCDAsyncSocket_AES128 16
#define EGCDAsyncSocket_PKCS7_PADDING 0




@interface EGCDAsyncSocket : GCDAsyncSocket


//Encryption
-(BOOL)startAESWithStrength:(BOOL)is256 key:(NSData*)cryptoKey;
-(BOOL)startAESWithStrength:(BOOL)is256 password:(NSString*)password salt:(NSString*)salt iterations:(int)iterations;
//Uses application bundle name for salt and defaults iterations to 2000;
-(BOOL)startAESWithStrength:(BOOL)is256 password:(NSString*)password;

-(BOOL)stopAES;
-(BOOL)isEncrypted;


@end

@interface CryptoHelper : NSObject
+(NSData*)generateKeyWithPIN:(NSString*)pin andSalt:(NSString*)salt strength:(int)strength iterations:(int)iterations;
+(NSData*)AESEncryptWithKey:(NSData*)key strength:(int)strength andData:(NSData*)data;
+(NSData*)AESDecryptWithKey:(NSData*)key strength:(int)strength andData:(NSData*)data;

@end