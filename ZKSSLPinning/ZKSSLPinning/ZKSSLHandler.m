//
//  ZKSSLHandler.m
//  ZKSSLPinning
//
//  Created by Zeeshan Khan on 14/02/15.
//  Copyright (c) 2015 Zeeshan. All rights reserved.
//

#import <openssl/x509.h>
#import <openssl/bio.h>
#import <openssl/err.h>
#import "ZKSSLHandler.h"

#pragma mark - Error

static void logOpenSSLErrors(void) {
    
    /* Wrapper function to print out any current OpenSSL errors
     * We could probably also just do ERR_print_errors_fp(stderr), but trying
     * to stick to the standard Cocoa interface here...
     */
    
    /* Print errors into a memory buffer */
    BIO *errBio = BIO_new(BIO_s_mem());
    ERR_print_errors(errBio);
    
    /* Get the pointer to the buffer */
    void *bytes;
    int len = BIO_get_mem_data(errBio, &bytes);
    
    /* Attempt to convert buffer to an NSString */
    NSData *data = [[NSData alloc] initWithBytesNoCopy:bytes length:len freeWhenDone:NO];
    NSString *errorMessages = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (errorMessages && [errorMessages length]) {
        NSLog(@"[SSL ERROR]: %@", errorMessages);
    }
    
	[errorMessages release];
    [data release];
    BIO_free(errBio);
}

#pragma mark - Validity

Boolean isCertificateExpired(NSDate *endDate) {

    NSTimeInterval distanceBetweenDates = [endDate timeIntervalSinceDate:[NSDate date]];
    NSInteger secondsBetweenDates = distanceBetweenDates / 60.0f;
    if (secondsBetweenDates <= 0)
        return YES;
    else
        return NO;
   
/* 
    // It doesn't check seconds.
    NSDate *later = [[NSDate date] laterDate:endDate];
    if ([later isEqualToDate:[NSDate date]])
        return YES;
    return NO;
 */
}

static NSDate *getCertificateValidity(ASN1_TIME *certificateASN1) {
    
    if (certificateASN1 == NULL)
        return nil;
    
    ASN1_GENERALIZEDTIME *certificateExpiryASN1Generalized = ASN1_TIME_to_generalizedtime(certificateASN1, NULL);
    if (certificateExpiryASN1Generalized != NULL) {
        
        unsigned char *certificateExpiryData = ASN1_STRING_data(certificateExpiryASN1Generalized);
        
        /* ASN1 generalized times look like this: "20131114230046Z"
         *                                format:  YYYYMMDDHHMMSS
         *                               indices:  01234567890123
         *                                                   1111
         * There are other formats (e.g. specifying partial seconds or time zones)
         * but this is good enough for our purposes since we only use the date and not the time.
         * (Source: http://www.obj-sys.com/asn1tutorial/node14.html )
         */
        
        NSString *strTime = [NSString stringWithUTF8String:(char *)certificateExpiryData];
        
        NSDateComponents *dateComponents = [[[NSDateComponents alloc] init] autorelease];
        dateComponents.year    = [[strTime substringWithRange:NSMakeRange(0, 4)] intValue];
        dateComponents.month = [[strTime substringWithRange:NSMakeRange(4, 2)] intValue];
        dateComponents.day     = [[strTime substringWithRange:NSMakeRange(6, 2)] intValue];
        dateComponents.hour    = [[strTime substringWithRange:NSMakeRange(8, 2)] intValue];
        dateComponents.minute = [[strTime substringWithRange:NSMakeRange(10, 2)] intValue];
        dateComponents.second = [[strTime substringWithRange:NSMakeRange(12, 2)] intValue];
        
        NSCalendar *calendar = [NSCalendar currentCalendar];
        NSDate *dateValidity = [calendar dateFromComponents:dateComponents];
        return dateValidity;
    }
    
    return nil;
}


static NSDate *getCertificateNotBefore(X509 *certificateX509) {
    
    if (certificateX509 != NULL) {
        ASN1_TIME *certificateASN1 = X509_get_notBefore(certificateX509);
        NSDate *dateNotBefore = getCertificateValidity(certificateASN1);
        return dateNotBefore;
    }
    return nil;
}

static NSDate *getCertificateNotAfter(X509 *certificateX509) {
    
    if (certificateX509 != NULL) {
        ASN1_TIME *certificateASN1 = X509_get_notAfter(certificateX509);
        NSDate *dateNotAfter = getCertificateValidity(certificateASN1);
        return dateNotAfter;
    }
    return nil;
}

#pragma mark - Issuer / Subject Details

static NSString * getCertificateNameForKey(X509_NAME *X509Name, const char *forKey) {
    
    if (X509Name == NULL)
        return nil;
    
    NSString *name = nil;
    int nid = OBJ_txt2nid(forKey);
    int index = X509_NAME_get_index_by_NID(X509Name, nid, -1);
    
    X509_NAME_ENTRY *certNameEntry = X509_NAME_get_entry(X509Name, index);
    if (certNameEntry) {
        
        ASN1_STRING *certNameASN1 = X509_NAME_ENTRY_get_data(certNameEntry);
        if (certNameASN1 != NULL) {
            
            unsigned char *certName = ASN1_STRING_data(certNameASN1);
            name = [NSString stringWithUTF8String:(char *)certName];
        }
    }
    return name;
}

static NSString* getCertificateIssuer(X509 *certificateX509) {
    
    if (certificateX509 == NULL)
        return nil;

    X509_NAME *issuerX509Name = X509_get_issuer_name(certificateX509);
    NSString *org = getCertificateNameForKey(issuerX509Name, "O");
    return org;
}

static NSString* getCertificateSubject(X509 *certificateX509) {
    
    if (certificateX509 == NULL)
        return nil;
    
    X509_NAME *subjectX509Name = X509_get_subject_name(certificateX509);
    NSString *cn = getCertificateNameForKey(subjectX509Name, "CN");
    return cn;
}

#pragma mark - X509 Creation

static X509 *createX509FromCertRef(SecCertificateRef ref) {
    
    CFDataRef data = SecCertificateCopyData(ref);
    if (data == NULL) {
        NSLog(@"[SSL ERROR]: Failed to retrieve DER data from Certificate Ref");
        return NULL;
    }
    
    BIO *mem = BIO_new_mem_buf((void *)CFDataGetBytePtr(data), CFDataGetLength(data));
    X509 *x509cert = NULL;
    x509cert = d2i_X509_bio(mem, NULL);
    BIO_free(mem);
    CFRelease(data);
    
    if (!x509cert) {
        NSLog(@"[SSL ERROR]: OpenSSL couldn't parse X509 Certificate");
        logOpenSSLErrors();
    }
    
    return x509cert;
}

#pragma mark - Print Certificate Information

static NSString* getSerialNo(X509 *certificateX509) {
    
    if (certificateX509 == NULL)
        return nil;
    
    ASN1_INTEGER *serial = X509_get_serialNumber(certificateX509);
    BIGNUM *bnser = ASN1_INTEGER_to_BN(serial, NULL);

    if (bnser) {

        //char *asciiHex = BN_bn2hex(bnser);
        //NSLog(@"Serial No: %@", [NSString stringWithUTF8String:asciiHex]);

        int n = BN_num_bytes(bnser);
        unsigned char outbuf[n];
        BN_bn2bin(bnser, outbuf);
        char *hexBuf = (char*) outbuf;
        NSMutableString *str = [NSMutableString new];
        for (int i=0; i<n; i++) {
            NSString *temp = [NSString stringWithFormat:@"%.6x", hexBuf[i]];
            [str appendString:[NSString stringWithFormat:@"%@ ", temp]];
        }
        [str replaceOccurrencesOfString:@"0000" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0, [str length])];
        [str replaceOccurrencesOfString:@"ffffff" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0, [str length])];
        
        return [str autorelease];
    }

    return nil;
}

NSString* getSHA1FingerPrint(X509 *certificateX509) {
    
    if (certificateX509 == NULL)
        return nil;

    NSString *strSHA1fingerprint = nil;
    int charLen = 20;
    char buf[charLen];
    const EVP_MD *digest = EVP_sha1();
    unsigned len;
    int rc = X509_digest(certificateX509, digest, (unsigned char*) buf, &len);
    
    if (rc != 0 && len == charLen) {

        char strbuf[2*charLen+1];
        unsigned char* readbuf = (unsigned char*)buf;
        void *writebuf = strbuf;
        size_t len = charLen;
        
        for(size_t i=0; i < len; i++) {
            char *l = (char*) (2*i + ((intptr_t) writebuf));
            sprintf(l, "%02x", readbuf[i]);
        }
        
//        NSLog(@"%s", strbuf);
        strSHA1fingerprint = [NSString stringWithUTF8String:strbuf];
    }
    
    return strSHA1fingerprint;
}

NSString* getMD5FingerPrint(X509 *certificateX509) {
    
    if (certificateX509 == NULL)
        return nil;

    NSString *strSHA1fingerprint = nil;
    int charLen = 16;
    char buf[charLen];
    const EVP_MD *digest = EVP_md5();
    unsigned len;
    int rc = X509_digest(certificateX509, digest, (unsigned char*) buf, &len);
    
    if (rc != 0 && len == charLen) {
        
        char strbuf[2*charLen+1];
        unsigned char* readbuf = (unsigned char*)buf;
        void *writebuf = strbuf;
        size_t len = charLen;
        
        for(size_t i=0; i < len; i++) {
            char *l = (char*) (2*i + ((intptr_t) writebuf));
            sprintf(l, "%02x", readbuf[i]);
        }
        
        //        NSLog(@"%s", strbuf);
        strSHA1fingerprint = [NSString stringWithUTF8String:strbuf];
    }
    
    return strSHA1fingerprint;
}

NSString* getCertSignatureAlgorithm(X509 *cert) {

    if (cert == NULL)
        return nil;

    int pkey_nid = OBJ_obj2nid(cert->cert_info->signature->algorithm);
	if (pkey_nid == NID_undef) {
		fprintf(stderr, "unable to find specified signature algorithm name.\n");
		return nil;
	}

    int PUBKEY_ALGO_LEN = 100;
    char buf[PUBKEY_ALGO_LEN];
	
	const char* sslbuf = OBJ_nid2ln(pkey_nid);
	if (strlen(sslbuf) > PUBKEY_ALGO_LEN) {
		fprintf(stderr, "public key algorithm name longer than allocated buffer.\n");
		return nil;
	}
	
	strncpy(buf, sslbuf, PUBKEY_ALGO_LEN);
    return [NSString stringWithUTF8String:sslbuf];
}

NSString* getPublicKeyAlgorithm(X509 *cert) {
    
    if (cert == NULL)
        return nil;

    int pkey_nid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
	if (pkey_nid == NID_undef) {
		fprintf(stderr, "unable to find specified signature algorithm name.\n");
		return nil;
	}
    
    int PUBKEY_ALGO_LEN = 100;
    char buf[PUBKEY_ALGO_LEN];
	
	const char* sslbuf = OBJ_nid2ln(pkey_nid);
	if (strlen(sslbuf) > PUBKEY_ALGO_LEN) {
		fprintf(stderr, "public key algorithm name longer than allocated buffer.\n");
		return nil;
	}
	
	strncpy(buf, sslbuf, PUBKEY_ALGO_LEN);
    return [NSString stringWithUTF8String:sslbuf];
}

NSDictionary* getExtensions(X509 *cert) {

    if (cert == NULL)
        return nil;

    STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;
    
	int num_of_exts;
	if (exts) {
		num_of_exts = sk_X509_EXTENSION_num(exts);
	} else {
		num_of_exts = 0;
	}
    
    NSMutableDictionary *dicExtentions = [NSMutableDictionary new];
	for (int i=0; i < num_of_exts; i++) {
        
		X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        if (ex == NULL) {
            NSLog(@"unable to extract extension from stack");
            break;
        }
		
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
        if (obj == NULL) {
            NSLog(@"unable to extract ASN1 object from extension");
            break;
        }
        
		BIO *ext_bio = BIO_new(BIO_s_mem());
        if (ext_bio == NULL) {
            NSLog(@"unable to allocate memory for extension value BIO");
            break;
        }
		
        if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
			M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
		}
        
		BUF_MEM *bptr;
		BIO_get_mem_ptr(ext_bio, &bptr);
		BIO_set_close(ext_bio, BIO_NOCLOSE);
        
		// remove newlines
		int lastchar = bptr->length;
		if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
			bptr->data[lastchar-1] = (char) 0;
		}
		if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
			bptr->data[lastchar] = (char) 0;
		}
        
		BIO_free(ext_bio);
        
		unsigned nid = OBJ_obj2nid(obj);
        NSString *strKey = nil;
		if (nid == NID_undef) {
			
            // no lookup found for the provided OID so nid came back as undefined.
            int EXTNAME_LEN = 60;
			char extname[EXTNAME_LEN];
			OBJ_obj2txt(extname, EXTNAME_LEN, (const ASN1_OBJECT *) obj, 1);
            strKey = [NSString stringWithUTF8String:extname];
		} else {
			
            // the OID translated to a NID which implies that the OID has a known sn/ln
			const char *c_ext_name = OBJ_nid2ln(nid);
            strKey = [NSString stringWithUTF8String:c_ext_name];
		}
		
		//printf("extension length is %zu\n", bptr->length);
        NSString *strVal = [NSString stringWithUTF8String:bptr->data];
        //NSLog(@"=== Name is %@ ===", strKey);
		//NSLog(@"Value: %@\n\n", strVal);
        if (strKey && strVal)
            [dicExtentions setObject:strVal forKey:strKey];
	}

    return [dicExtentions autorelease];
}

NSArray* getCertificateInfo(SecTrustRef trust) {
    
    if (trust == NULL)
        return nil;

    OpenSSL_add_all_digests();
    int chain_len = SecTrustGetCertificateCount(trust);
    //NSLog(@"Certificate Count: %d", chain_len);
    
    NSMutableArray *arrCerInfo = [NSMutableArray new];
    for (int cnt=0; cnt<chain_len; cnt++) {
        
        SecCertificateRef certRef = SecTrustGetCertificateAtIndex(trust, cnt);
        if (certRef != NULL) {
            
            X509 *certificate = createX509FromCertRef(certRef);
            if (certificate != nil) {
                
                NSMutableDictionary *dicCertInfo = [NSMutableDictionary new];
                
                NSString *strSHA1 = getSHA1FingerPrint(certificate);
                //NSLog(strSHA1);
                if (strSHA1) [dicCertInfo setObject:strSHA1 forKey:@"SHA1 Fingerprint"];
                
                
                NSString *strMD5 = getMD5FingerPrint(certificate);
                //NSLog(strMD5);
                if (strMD5) [dicCertInfo setObject:strMD5 forKey:@"MD5 Fingerprint"];
                
                
                NSString *strCertSigAlgo = getCertSignatureAlgorithm(certificate);
                //NSLog(strCertSigAlgo);
                if (strCertSigAlgo) [dicCertInfo setObject:strCertSigAlgo forKey:@"Certificate Signature Algorithm"];
                
                
                //Version - Parsing the certificate version is straight-foward; the only oddity is that it is zero-indexed:
                //            X509_CINF *certInfo = certificate->cert_info;
                //            ASN1_INTEGER *ver = certInfo->version;
                //            BIGNUM *bnser = ASN1_INTEGER_to_BN(ver, NULL);
                //            char *asciiHex = BN_bn2hex(bnser);
                //            NSString *strVersion = [NSString stringWithUTF8String:asciiHex];
                //NSLog(@"Version: %@", strVersion);
                int version = ((int) X509_get_version(certificate)) + 1;
                [dicCertInfo setObject:[NSNumber numberWithInteger:version] forKey:@"Version"];
                //NSLog(@"%ld", X509_get_version(rootCert));
                
                
                NSString *strSerialNo = getSerialNo(certificate);
                //NSLog(@"Serial No: %@", strSerialNo);
                if (strSerialNo) [dicCertInfo setObject:strSerialNo forKey:@"Serial Number"];
                
                
                NSDate *rootNA = getCertificateNotAfter(certificate);
                //NSLog(@"Serial No: %@", rootNA);
                if (rootNA) [dicCertInfo setObject:rootNA forKey:@"Not After"];
                
                
                NSDate *rootNB = getCertificateNotBefore(certificate);
                //NSLog(@"Serial No: %@", rootNB);
                if (rootNB) [dicCertInfo setObject:rootNB forKey:@"Not Before"];
                
                
                ASN1_BIT_STRING *pubKey = X509_get0_pubkey_bitstr(certificate);
                
                NSMutableString *publicKeyString = [NSMutableString new];
                for (int i=0; i<pubKey->length; i++) {
                    NSString *temp = [NSString stringWithFormat:@"%.6x", pubKey->data[i]];
                    [publicKeyString appendString:[NSString stringWithFormat:@"%@ ", temp]];
                }
                [publicKeyString replaceOccurrencesOfString:@"0000" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0, [publicKeyString length])];
                [publicKeyString replaceOccurrencesOfString:@"ffffff" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0, [publicKeyString length])];
                //NSLog(@"Public Key %@", publicKeyString);
                if (publicKeyString) [dicCertInfo setObject:publicKeyString forKey:@"Public Key"];
                [publicKeyString release]; publicKeyString = nil;
                
                NSString *strPubKeyAlgo = getPublicKeyAlgorithm(certificate);
                //NSLog(strPubKeyAlgo);
                if (strPubKeyAlgo) [dicCertInfo setObject:strPubKeyAlgo forKey:@"Public Key Algorithm"];

                
                X509_NAME *subject = X509_get_subject_name(certificate);
                //NSLog(@"=== Subject ===");
                const char *labels[] = {"CN", "E", "OU", "O", "L", "S", "C", "ST"};
                //size_t len = strlen(labels);
                for (int l=0; l<8; l++) {
                    const char *lab = labels[l];
                    NSString *strVal = getCertificateNameForKey(subject, lab);
                    //NSLog(@"%s: %@", lab, strVal);
                    if (strVal) [dicCertInfo setObject:strVal forKey:[NSString stringWithFormat:@"Subject - %s",lab]];
                }
                
                
                X509_NAME *issuer = X509_get_issuer_name(certificate);
                //NSLog(@"=== Issuer ===");
                //size_t len = strlen(labels);
                for (int l=0; l<8; l++) {
                    const char *lab = labels[l];
                    NSString *strVal = getCertificateNameForKey(issuer, lab);
                    //NSLog(@"%s: %@", lab, strVal);
                    if (strVal) [dicCertInfo setObject:strVal forKey:[NSString stringWithFormat:@"Issuer - %s",lab]];
                }

                NSDictionary *dicExt = getExtensions(certificate);
                if (dicExt)
                    [dicCertInfo setObject:dicExt forKey:@"Other Arbitrary Extensions"];
                
                //NSLog(@"Cert Info: %@", dicCertInfo);
                [arrCerInfo addObject:dicCertInfo];
                [dicCertInfo release]; dicCertInfo = nil;

                X509_free(certificate);

            } // Close X509 certificate
            
        } // Close certRef

    } // Close loop

    //NSLog(@"Cert Info: %@", arrCerInfo);
    return [arrCerInfo autorelease];
}

@implementation ZKSSLHandler

+ (void)printSSLCertificate:(NSURLProtectionSpace *)protectionSpace {
    
    if (protectionSpace != nil) {
        
        /* a SecTrustRef instance for the server certificates */
        SecTrustRef serverCertificates = protectionSpace.serverTrust;
        if (serverCertificates != nil) {
            
            SecTrustResultType res;
            OSStatus status = SecTrustEvaluate(serverCertificates, &res);
            
            if (status == errSecSuccess && ((res == kSecTrustResultProceed) || (res == kSecTrustResultUnspecified))) {

                NSArray *certInfo = getCertificateInfo(serverCertificates);
                NSLog(@"[SSL Info]: Certificate for Host:- %@://%@:%d  \n  %@", protectionSpace.protocol, protectionSpace.host, protectionSpace.port, certInfo);
            }
            else {
                NSLog(@"[SSL Info]: Can't proceed with OSStatus: %d & SecTrustResultType: %d", (NSInteger)status, res);
            }
        }
        else {
            NSLog(@"[SSL Info]: SecTrustRef is nil");
        }
    }
    else {
        NSLog(@"[SSL Info]: NSURLProtectionSpace is nil.");
    }
    
}


@end
