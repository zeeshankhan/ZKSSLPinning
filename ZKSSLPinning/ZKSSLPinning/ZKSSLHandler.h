//
//  ZKSSLHandler.h
//  ZKSSLPinning
//
//  Created by Zeeshan Khan on 14/02/15.
//  Copyright (c) 2015 Zeeshan. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface ZKSSLHandler : NSObject

+ (void)printSSLCertificate:(NSURLProtectionSpace *)protectionSpace;

@end