//
//  AppDelegate.m
//  ZKSSLPinning
//
//  Created by Zeeshan Khan on 10/02/15.
//  Copyright (c) 2015 Zeeshan. All rights reserved.
//

#import "AppDelegate.h"
#import "ZKSSLHandler.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor whiteColor];
    [self.window makeKeyAndVisible];
    [self addButton];
    return YES;
}

- (void)addButton {
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeRoundedRect];
    btn.layer.borderWidth = .8;
    btn.layer.cornerRadius = 3;
    [btn setTitle:@"SSL Info" forState:UIControlStateNormal];
    btn.layer.borderColor = btn.titleLabel.textColor.CGColor;
    btn.frame = CGRectMake(10, 10, 200, 35);
    btn.center = self.window.center;
    [btn addTarget:self action:@selector(sslInfomation) forControlEvents:UIControlEventTouchUpInside];
    [self.window addSubview:btn];
}

- (void)sslInfomation {
    
    [[UIApplication sharedApplication] setNetworkActivityIndicatorVisible:YES];
    NSURLRequest *req = [[NSURLRequest alloc] initWithURL:[NSURL URLWithString:@"https://www.mozilla.org/en-US/"]];
    [NSURLConnection connectionWithRequest:req delegate:self];
}

#pragma mark - Connection Delegates

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    return YES;
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    //[ZKSSLHandler printSSLCertificate:challenge.protectionSpace];
    NSLog(@"Is ssl verified: %@", @([ZKSSLHandler verifySSLCertificates:challenge.protectionSpace]));
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    [[UIApplication sharedApplication] setNetworkActivityIndicatorVisible:NO];
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    [[UIApplication sharedApplication] setNetworkActivityIndicatorVisible:NO];
}


@end
