//
//  zsign.mm
//  feather
//
//  Created by HAHALOSAH on 5/22/24.
//

#include "zsign.hpp"
#include "common.h"
#include "openssl.h"
#include "macho.h"
#include "bundle.h"
#include "openssl.h"
#include "timer.h"
#include "archive.h"

#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/asn1.h>

#include <memory>

extern "C" {

bool CheckIfSigned(NSString *filePath) {
	ZTimer gtimer;
	@autoreleasepool {
		std::string filePathStr = [filePath UTF8String];
		
		ZMachO machO;
		bool initSuccess = machO.Init(filePathStr.c_str());
		if (!initSuccess) {
			gtimer.Print(">>> Failed to initialize ZMachO.");
			return false;
		}
		
		bool success = machO.CheckSignature();
		
		machO.Free();
		
		if (success) {
			gtimer.Print(">>> MachO is signed!");
			return true;
		} else {
			gtimer.Print(">>> MachO is not signed.");
			return false;
		}
	}
}

bool InjectDyLib(NSString *filePath, NSString *dylibPath, bool weakInject) {
	ZTimer gtimer;
	@autoreleasepool {
		std::string filePathStr = [filePath UTF8String];
		std::string dylibPathStr = [dylibPath UTF8String];
		
		ZMachO machO;
		bool initSuccess = machO.Init(filePathStr.c_str());
		if (!initSuccess) {
			gtimer.Print(">>> Failed to initialize ZMachO.");
			return false;
		}
		
		bool success = machO.InjectDylib(weakInject, dylibPathStr.c_str());
		
		machO.Free();
		
		if (success) {
			gtimer.Print(">>> Dylib injected successfully!");
			return true;
		} else {
			gtimer.Print(">>> Failed to inject dylib.");
			return false;
		}
	}
}

bool UninstallDylibs(NSString *filePath, NSArray<NSString *> *dylibPathsArray) {
	ZTimer gtimer;
	@autoreleasepool {
		std::string filePathStr = [filePath UTF8String];
		std::set<std::string> dylibsToRemove;
		
		for (NSString *dylibPath in dylibPathsArray) {
			dylibsToRemove.insert([dylibPath UTF8String]);
		}
		
		ZMachO machO;
		bool initSuccess = machO.Init(filePathStr.c_str());
		if (!initSuccess) {
			gtimer.Print(">>> Failed to initialize ZMachO.");
			return false;
		}
		
		machO.RemoveDylibs(dylibsToRemove);
		
		machO.Free();
		
		gtimer.Print(">>> Dylibs uninstalled successfully!");
		return true;
	}
}

NSArray<NSString *> *ListDylibs(NSString *filePath) {
	ZTimer gtimer;
	@autoreleasepool {
		NSMutableArray<NSString *> *dylibPathsArray = [NSMutableArray array];
		
		std::string filePathStr = [filePath UTF8String];
		
		ZMachO machO;
		bool initSuccess = machO.Init(filePathStr.c_str());
		if (!initSuccess) {
			gtimer.Print(">>> Failed to initialize ZMachO.");
			return nil;
		}
		
		std::vector<std::string> dylibPaths = machO.ListDylibs();
		
		if (!dylibPaths.empty()) {
			gtimer.Print(">>> List of dylibs in the Mach-O file:");
			for (const std::string &dylibPath : dylibPaths) {
				NSString *dylibPathStr = [NSString stringWithUTF8String:dylibPath.c_str()];
				[dylibPathsArray addObject:dylibPathStr];
			}
		} else {
			gtimer.Print(">>> No dylibs found in the Mach-O file.");
		}
		
		machO.Free();
		
		return [dylibPathsArray copy];
	}
}

bool ChangeDylibPath(NSString *filePath, NSString *oldPath, NSString *newPath) {
	ZTimer gtimer;
	@autoreleasepool {
		std::string filePathStr = [filePath UTF8String];
		std::string oldPathStr = [oldPath UTF8String];
		std::string newPathStr = [newPath UTF8String];
		
		ZMachO machO;
		bool initSuccess = machO.Init(filePathStr.c_str());
		if (!initSuccess) {
			gtimer.Print(">>> Failed to initialize ZMachO.");
			return false;
		}
		
		bool success = machO.ChangeDylibPath(oldPathStr.c_str(), newPathStr.c_str());
		
		machO.Free();
		
		if (success) {
			gtimer.Print(">>> Dylib path changed successfully!");
			return true;
		} else {
			gtimer.Print(">>> Failed to change dylib path.");
			return false;
		}
	}
}

int zsign(
	NSString *app,
	NSString *prov,
	NSString *key,
	NSString *pass,
	NSString *entitlement,
	NSString *bundleid,
	NSString *displayname,
	NSString *bundleversion,
	bool adhoc,
	bool excludeprovion,
	void(^completionHandler)(BOOL success)
) {
	ZTimer atimer;
	ZTimer gtimer;
	
	bool bForce = true;
	bool bWeakInject = false;
	bool bAdhoc = adhoc;
	bool bSHA256Only = false;
	
	string strCertFile;
	string strPKeyFile;
	string strProvFile;
	string strPassword;
	string strBundleId;
	string strBundleVersion;
	string strDisplayName;
	string strEntitleFile;
	vector<string> arrDylibFiles;
	vector<string> arrDisDylibFiles;
	
	strPKeyFile = [key cStringUsingEncoding:NSUTF8StringEncoding];
	strProvFile = [prov cStringUsingEncoding:NSUTF8StringEncoding];
	strPassword = [pass cStringUsingEncoding:NSUTF8StringEncoding];
	strEntitleFile = [entitlement cStringUsingEncoding:NSUTF8StringEncoding];
	
	strBundleId = [bundleid cStringUsingEncoding:NSUTF8StringEncoding];
	strDisplayName = [displayname cStringUsingEncoding:NSUTF8StringEncoding];
	strBundleVersion = [bundleversion cStringUsingEncoding:NSUTF8StringEncoding];
	
	string strPath = [app cStringUsingEncoding:NSUTF8StringEncoding];
	if (!ZFile::IsFileExists(strPath.c_str())) {
		ZLog::ErrorV(">>> Invalid path! %s\n", strPath.c_str());
		return -1;
	}
	
	ZSignAsset zsa;
	if (!zsa.Init(strCertFile, strPKeyFile, strProvFile, strEntitleFile, strPassword, bAdhoc, bSHA256Only, false)) {
		return -1;
	}
	
	bool bEnableCache = true;
	string strFolder = strPath;
	
	atimer.Reset();
	ZBundle bundle;
	bool bRet = bundle.SignFolder(&zsa, strFolder, strBundleId, strBundleVersion, strDisplayName, arrDylibFiles, arrDisDylibFiles, bForce, bWeakInject, bEnableCache, excludeprovion);
	ZLog::PrintV(">>> Signing:\t%s %s\n", strPath.c_str(), (bAdhoc ? " (Ad-hoc)" : ""));
	atimer.PrintResult(bRet, ">>> Signed %s!", bRet ? "OK" : "Failed");
	
	completionHandler(bRet);
	
	gtimer.Print(">>> Done.");
	return bRet ? 0 : -1;
}


int checkCert(
	NSString *prov,
	NSString *key,
	NSString *pass,
	void(^completionHandler)(int status, NSDate* expirationDate, NSString *error)
) {
	string strCertFile;
	string strPKeyFile;
	string strProvFile;
	string strPassword;
	string strEntitleFile;
		
	if (!key || !prov || !pass) {
		completionHandler(2, nil, @"One or more required paths or password is missing.");
		return -1;
	}
		
	strPKeyFile = [key cStringUsingEncoding:NSUTF8StringEncoding];
	strProvFile = [prov cStringUsingEncoding:NSUTF8StringEncoding];
	strPassword = [pass cStringUsingEncoding:NSUTF8StringEncoding];

	ZSignAsset zsa;
		
	if (!zsa.Init(strCertFile, strPKeyFile, strProvFile, strEntitleFile, strPassword, false, false, false)) {
		completionHandler(2, nil, @"Unable to initialize certificate. Please check your password.");
		return -1;
	}

	X509* cert = (X509*)zsa.m_x509Cert;
	if (!cert) {
		completionHandler(2, nil, @"Unable to load certificate.");
		return -2;
	}

	using BIOPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
	BIOPtr issuerBIO(nullptr, BIO_free);
	unsigned long issuerHash = X509_issuer_name_hash(cert);
	if (0x817d2f7a == issuerHash) {
		issuerBIO.reset(BIO_new_mem_buf(ZSignAsset::s_szAppleDevCACert, (int)strlen(ZSignAsset::s_szAppleDevCACert)));
	} else if (0x9b16b75c == issuerHash) {
		issuerBIO.reset(BIO_new_mem_buf(ZSignAsset::s_szAppleDevCACertG3, (int)strlen(ZSignAsset::s_szAppleDevCACertG3)));
	} else {
		completionHandler(2, nil, @"Unable to determine issuer of the certificate. It is signed by Apple Developer?");
		return -3;
	}

	if (!issuerBIO) {
		completionHandler(2, nil, @"Unable to initialize issuer certificate.");
		return -4;
	}

	using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
	X509Ptr issuer(PEM_read_bio_X509(issuerBIO.get(), NULL, 0, NULL), X509_free);
	if (!issuer) {
		completionHandler(2, nil, @"Unable to load issuer certificate.");
		return -5;
	}

	auto freeAIA = [](STACK_OF(ACCESS_DESCRIPTION)* value) {
		if (value) sk_ACCESS_DESCRIPTION_pop_free(value, ACCESS_DESCRIPTION_free);
	};
	std::unique_ptr<STACK_OF(ACCESS_DESCRIPTION), decltype(freeAIA)> aia(
		(STACK_OF(ACCESS_DESCRIPTION)*)X509_get_ext_d2i(cert, NID_info_access, 0, 0),
		freeAIA
	);
	if (!aia) {
		completionHandler(2, nil, @"No AIA (OCSP) extension found in certificate");
		return -6;
	}

	ASN1_IA5STRING* uri = nullptr;
	for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia.get()); i++) {
		ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia.get(), i);
		if (OBJ_obj2nid(ad->method) == NID_ad_OCSP &&
			ad->location->type == GEN_URI) {
			uri = ad->location->d.uniformResourceIdentifier;
			break;
		}
	}

	if (!uri || ASN1_STRING_length(uri) <= 0) {
		completionHandler(2, nil, @"No OCSP URI found in certificate.");
		return -7;
	}

	NSString *urlString = [[NSString alloc] initWithBytes:ASN1_STRING_get0_data(uri)
		length:ASN1_STRING_length(uri)
		encoding:NSASCIIStringEncoding];
	NSURL *url = urlString ? [NSURL URLWithString:urlString] : nil;
	NSString *scheme = url.scheme.lowercaseString;
	if (!url || (!([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"]))) {
		completionHandler(2, nil, @"Certificate contains an invalid OCSP URL.");
		return -8;
	}

	using OCSPRequestPtr = std::unique_ptr<OCSP_REQUEST, decltype(&OCSP_REQUEST_free)>;
	using OCSPCertIDPtr = std::unique_ptr<OCSP_CERTID, decltype(&OCSP_CERTID_free)>;
	OCSPRequestPtr req(OCSP_REQUEST_new(), OCSP_REQUEST_free);
	OCSPCertIDPtr requestCertID(OCSP_cert_to_id(nullptr, cert, issuer.get()), OCSP_CERTID_free);
	OCSPCertIDPtr responseCertID(OCSP_cert_to_id(nullptr, cert, issuer.get()), OCSP_CERTID_free);
	if (!req || !requestCertID || !responseCertID) {
		completionHandler(2, nil, @"Unable to create OCSP request.");
		return -9;
	}
	if (!OCSP_request_add0_id(req.get(), requestCertID.get())) {
		completionHandler(2, nil, @"Unable to add certificate to OCSP request.");
		return -10;
	}
	requestCertID.release(); // owned by req

	NSDate *expirationDate = nil;
	if (const ASN1_TIME *notAfter = X509_get0_notAfter(cert)) {
		struct tm value = {};
		if (ASN1_TIME_to_tm(notAfter, &value) == 1) {
			NSDateComponents *components = [[NSDateComponents alloc] init];
			components.year = value.tm_year + 1900;
			components.month = value.tm_mon + 1;
			components.day = value.tm_mday;
			components.hour = value.tm_hour;
			components.minute = value.tm_min;
			components.second = value.tm_sec;
			NSCalendar *calendar = [[NSCalendar alloc] initWithCalendarIdentifier:NSCalendarIdentifierGregorian];
			calendar.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
			expirationDate = [calendar dateFromComponents:components];
		}
	}

	unsigned char* encodedRequest = nullptr;
	int encodedLength = i2d_OCSP_REQUEST(req.get(), &encodedRequest);
	auto freeOpenSSL = [](unsigned char* value) { OPENSSL_free(value); };
	std::unique_ptr<unsigned char, decltype(freeOpenSSL)> encodedRequestOwner(encodedRequest, freeOpenSSL);
	if (encodedLength <= 0 || !encodedRequest) {
		completionHandler(2, expirationDate, @"Unable to encode OCSP request.");
		return -11;
	}

	using X509StorePtr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
	X509StorePtr validationStore(X509_STORE_new(), X509_STORE_free);
	if (!validationStore || X509_STORE_add_cert(validationStore.get(), issuer.get()) != 1) {
		completionHandler(2, expirationDate, @"Unable to initialize OCSP validation.");
		return -12;
	}

	NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
	[request setHTTPMethod:@"POST"];
	[request setHTTPBody:[NSData dataWithBytes:encodedRequest length:(NSUInteger)encodedLength]];
	[request setValue:@"application/ocsp-request" forHTTPHeaderField:@"Content-Type"];
	[request setValue:@"application/ocsp-response" forHTTPHeaderField:@"Accept"];

	OCSP_CERTID *asyncCertID = responseCertID.release();
	X509_STORE *asyncValidationStore = validationStore.release();
	void (^finish)(int, NSDate *, NSString *) = ^(int status, NSDate *date, NSString *error) {
		OCSP_CERTID_free(asyncCertID);
		X509_STORE_free(asyncValidationStore);
		completionHandler(status, date, error);
	};

	NSURLSession *session = [NSURLSession sharedSession];
	NSURLSessionDataTask *task = [session dataTaskWithRequest:request
											completionHandler:^(NSData * _Nullable data,
																	NSURLResponse * _Nullable response,
																	NSError * _Nullable error) {
		if (error) {
			finish(2, expirationDate, error.localizedDescription);
			return;
		}

		if (![response isKindOfClass:NSHTTPURLResponse.class] || ((NSHTTPURLResponse *)response).statusCode != 200 || !data.length) {
			finish(2, expirationDate, @"Invalid OCSP HTTP response.");
			return;
		}

		const unsigned char *responseBytes = (const unsigned char *)data.bytes;
		using OCSPResponsePtr = std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)>;
		OCSPResponsePtr ocspResponse(d2i_OCSP_RESPONSE(nullptr, &responseBytes, (long)data.length), OCSP_RESPONSE_free);
		if (!ocspResponse || OCSP_response_status(ocspResponse.get()) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
			finish(2, expirationDate, @"Invalid OCSP response.");
			return;
		}

		using OCSPBasicResponsePtr = std::unique_ptr<OCSP_BASICRESP, decltype(&OCSP_BASICRESP_free)>;
		OCSPBasicResponsePtr basic(OCSP_response_get1_basic(ocspResponse.get()), OCSP_BASICRESP_free);
		if (!basic || OCSP_basic_verify(basic.get(), nullptr, asyncValidationStore, 0) != 1) {
			finish(2, expirationDate, @"Unable to verify OCSP response.");
			return;
		}

		int status = V_OCSP_CERTSTATUS_UNKNOWN;
		int reason = 0;
		ASN1_GENERALIZEDTIME *revocationTime = nullptr;
		ASN1_GENERALIZEDTIME *thisUpdate = nullptr;
		ASN1_GENERALIZEDTIME *nextUpdate = nullptr;
		if (!OCSP_resp_find_status(basic.get(), asyncCertID, &status, &reason, &revocationTime, &thisUpdate, &nextUpdate) ||
			!OCSP_check_validity(thisUpdate, nextUpdate, 300, -1)) {
			finish(2, expirationDate, @"OCSP response is missing or expired.");
			return;
		}

		finish(status, expirationDate, nil);
	}];

	[task resume];
	return 1;
}



}
