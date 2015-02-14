//
//  ZKSSLHandler.h
//  ZKCryptography
//
//  Created by Zeeshan Khan on 11/02/14.
//  Copyright (c) 2014 Zeeshan. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface ZKSSLHandler : NSObject

+ (void)printSSLCertificate:(NSURLProtectionSpace *)protectionSpace;

@end