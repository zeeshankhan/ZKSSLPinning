//
//  ZKSSLHandler.h
//  ZKSSLPinning
//
//  Created by Zeeshan Khan on 14/02/15.
//  Copyright (c) 2015 Zeeshan. All rights reserved.
//

// Content across the web about OpenSSL
// https://zakird.com/2013/10/13/certificate-parsing-with-openssl/
// http://stackoverflow.com/questions/14645779/parsing-certificate-using-openssl-x509-h
// https://www.digicert.com/ssl.htm
// https://www.duosecurity.com/blog/working-around-phoney-ssl-certificates-on-ios-with-openssl
// https://github.com/akgood/iOSBasicConstraintsWorkaround


#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface ZKSSLHandler : NSObject

+ (void)printSSLCertificate:(NSURLProtectionSpace *)protectionSpace;

@end