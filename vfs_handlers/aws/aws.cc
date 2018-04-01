// This file is part of MLDB. Copyright 2015 mldb.ai inc. All rights reserved.

/* aws.cc
   Jeremy Barnes, 8 August 2013
   Copyright (c) 2013 mldb.ai inc.  All rights reserved.

*/

#include "aws.h"
#include "mldb/arch/format.h"
#include "mldb/jml/utils/string_functions.h"
#include <iostream>

#include "xml_helpers.h"
#include <boost/algorithm/string.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "crypto++/sha.h"
#include "crypto++/md5.h"
#include "crypto++/hmac.h"
#include "crypto++/base64.h"
#include "crypto++/hex.h"
#pragma GCC diagnostic pop


using namespace std;
using namespace ML;

namespace MLDB {

// Fix GCC error message about unused function
auto __fixGccError = &CryptoPP::StringNarrow;

template<class Hash>
std::string
AwsApi::
hmacDigest(const std::string & stringToSign,
           const std::string & accessKey)
{
    size_t digestLen = Hash::DIGESTSIZE;
    byte digest[digestLen];
    CryptoPP::HMAC<Hash> hmac((byte *)accessKey.c_str(), accessKey.length());
    hmac.CalculateDigest(digest,
                         (byte *)stringToSign.c_str(),
                         stringToSign.length());

    return std::string((const char *)digest,
                       digestLen);
}

std::string
AwsApi::
hmacSha1Digest(const std::string & stringToSign,
               const std::string & accessKey)
{
    return hmacDigest<CryptoPP::SHA1>(stringToSign, accessKey);
}

std::string
AwsApi::
hmacSha256Digest(const std::string & stringToSign,
                 const std::string & accessKey)
{
    return hmacDigest<CryptoPP::SHA256>(stringToSign, accessKey);
}

std::string
AwsApi::
sha256Digest(const std::string & stringToSign)
{
    typedef CryptoPP::SHA256 Hash;
    size_t digestLen = Hash::DIGESTSIZE;
    byte digest[digestLen];
    Hash h;
    h.CalculateDigest(digest,
                      (byte *)stringToSign.c_str(),
                      stringToSign.length());
    
    return std::string((const char *)digest,
                       digestLen);
}

template<typename Encoder>
std::string
AwsApi::
encodeDigest(const std::string & digest)
{
    char outBuf[256];

    Encoder encoder;
    encoder.Put((byte *)digest.c_str(), digest.size());
    encoder.MessageEnd();
    size_t got = encoder.Get((byte *)outBuf, 256);
    outBuf[got] = 0;

    //cerr << "signing " << digest.size() << " characters" << endl;
    //cerr << "last character is " << (int)outBuf[got - 1] << endl;
    //cerr << "got " << got << " characters" << endl;

    string result(outBuf, outBuf + got);
    boost::trim(result);
    return result;
}

std::string
AwsApi::
base64EncodeDigest(const std::string & digest)
{
    return encodeDigest<CryptoPP::Base64Encoder>(digest);
}

std::string
AwsApi::
hexEncodeDigest(const std::string & digest)
{
    return ML::lowercase(encodeDigest<CryptoPP::HexEncoder>(digest));
}

std::string
AwsApi::
uriEncode(const std::string & str)
{
    std::string result;
    for (auto c: str) {

        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            result += c;
        else result += MLDB::format("%%%02X", c);
    }

    return result;
}

std::string
AwsApi::
uriEncode(const Utf8String & str)
{
    return uriEncode(str.rawString());
}

std::string
AwsApi::
escapeResource(const std::string & resource)
{
    if (resource.size() == 0) {
        throw MLDB::Exception("empty resource name");
    }

    if (resource[0] != '/') {
        throw MLDB::Exception("resource name must start with a '/'");
    }

    return "/" + uriEncode(resource.substr(1));
}

std::string
AwsApi::
signingKeyV4(const std::string & accessKey,
             const std::string & date,
             const std::string & region,
             const std::string & service,
             const std::string & signing)
{
    auto hmac = [&] (const std::string & key, const std::string & data)
        {
            return hmacSha256Digest(data, key);
        };
    
    string signingKey
        = hmac(hmac(hmac(hmac("AWS4" + accessKey,
                              date),
                         region),
                    service),
               signing);
    return signingKey;
}

std::string
AwsApi::
signV4(const std::string & stringToSign,
       const std::string & accessKey,
       const std::string & date,
       const std::string & region,
       const std::string & service,
       const std::string & signing)
{
    
    string signingKey = signingKeyV4(accessKey, date, region, service, signing);
    //cerr << "signingKey " << hexEncodeDigest(signingKey) << endl;
    return hexEncodeDigest(hmacSha256Digest(stringToSign, signingKey));
}

void
AwsApi::
addSignatureV4(BasicRequest & request,
               std::string service,
               std::string region,
               std::string accessKeyId,
               std::string accessKey,
               Date now,
               PayloadDigest digest)
{
    string dateStr = now.print("%Y%m%dT%H%M%SZ");

    //cerr << "dateStr = " << dateStr << endl;

    request.headers.push_back({"x-amz-date", dateStr});

    string payloadHash;
    if (digest == PLD_ON || digest == PLD_IMPLICIT)
        payloadHash = hexEncodeDigest(sha256Digest(request.payload));
    else payloadHash = "UNSIGNED-PAYLOAD";

    if (digest != PLD_IMPLICIT)
        request.headers.push_back({"x-amz-content-sha256", payloadHash});
    
    string canonicalHeaders;
    string signedHeaders;

    if (!request.headers.empty()) {
        RestParams headers = request.headers;
        for (auto & h: headers) {
            h.first = lowercase(h.first);
            boost::trim(h.second);
        }
        std::sort(headers.begin(), headers.end());
        
        for (auto h: headers) {
            canonicalHeaders += h.first.rawString() + ":" + h.second.rawString() + "\n";
            signedHeaders += h.first.rawString() + ";";
        }

        signedHeaders.erase(signedHeaders.size() - 1);
    }

    string canonicalQueryParams;

    if (!request.queryParams.empty()) {
        RestParams queryParams = request.queryParams;
        std::sort(queryParams.begin(), queryParams.end());
        
        for (auto h: queryParams)
            canonicalQueryParams += uriEncode(h.first) + "=" + uriEncode(h.second) + "&";

        canonicalQueryParams.erase(canonicalQueryParams.size() - 1);
    }

    //cerr << "payload = " << request.payload << endl;

    string relativeUri
        = (!request.relativeUri.empty() && request.relativeUri[0] == '/')
        ? request.relativeUri
        : "/" + request.relativeUri;
    
    string canonicalRequest
        = request.method + "\n"
        + relativeUri + "\n"
        + canonicalQueryParams + "\n"
        + canonicalHeaders + "\n"
        + signedHeaders + "\n"
        + payloadHash;

    //cerr << "canonicalRequest = " << canonicalRequest << endl;

    RestParams authParams;

    string authHeader = "AWS4-HMAC-SHA256 ";

    auto addParam = [&] (string key, string value)
        {
            authHeader += key + "=" + value + ", ";
        };



    string credentialScope = string(dateStr, 0, 8) + "/" + region + "/" + service + "/" + "aws4_request";
    
    addParam("Credential", accessKeyId + "/" + credentialScope);
    addParam("SignedHeaders", signedHeaders);
    
    //addParam("SignatureVersion", "4");
    //addParam("SignatureMethod", "AWS4-HMAC-SHA256");

    string hashedCanonicalRequest = hexEncodeDigest(sha256Digest(canonicalRequest));
    
    string stringToSign
        = "AWS4-HMAC-SHA256\n"
        + dateStr + "\n"
        + credentialScope + "\n"
        + hashedCanonicalRequest;

    //cerr << "stringToSign = " << stringToSign << endl;

    string signature = AwsApi::signV4(stringToSign, accessKey, string(dateStr, 0, 8), region, service);
    addParam("Signature", signature);

    authHeader.erase(authHeader.size() - 2);

    request.headers.push_back({"Authorization", authHeader});
}



/*****************************************************************************/
/* AWS BASIC API                                                             */
/*****************************************************************************/

#if 0

AwsBasicApi(const std::string & accessKeyId,
                    const std::string & accessKey,
                    const std::string & service,
                    const std::string & serviceUri = "",
                    const std::string & region = "us-east-1");

    void init(const std::string & accessKeyId,
              const std::string & accessKey,
              const std::string & service,
              const std::string & serviceUri = "",
              const std::string & region = "us-east-1");
              
    std::string accessKeyId;
    std::string accessKey;
    std::string serviceUri;
    std::string service;
    std::string region;

    HttpRestProxy proxy;


void
AwsBasicApi::
init(const std::string & accessKeyId,
     const std::string & accessKey,
     const std::string & serviceUri)
{
    this->serviceUri = serviceUri;

}

#endif

AwsBasicApi::
AwsBasicApi()
{
}

void
AwsBasicApi::
setService(const std::string & serviceName,
           const std::string & protocol,
           const std::string & region)
{
    this->serviceName = serviceName;
    this->protocol = protocol;
    this->region = region;

    this->serviceHost = serviceName + "." + region + ".amazonaws.com";
    this->serviceUri = protocol + "://" + serviceHost + "/";

    proxy.init(serviceUri);
    //proxy.debug = true;
}

void
AwsBasicApi::
setCredentials(const std::string & accessKeyId,
               const std::string & accessKey)
{
    this->accessKeyId = accessKeyId;
    this->accessKey = accessKey;
}

AwsBasicApi::BasicRequest
AwsBasicApi::
signPost(RestParams && params, const std::string & resource,
         Date date, PayloadDigest digest)
{
    BasicRequest result;
    result.method = "POST";
    result.relativeUri = resource;
    result.headers.push_back({"Host", serviceHost});
    result.headers.push_back({"Content-Type", "application/x-www-form-urlencoded; charset=utf-8"});

    std::string encodedPayload;

    for (auto p: params) {
        encodedPayload += uriEncode(p.first) + "=";
        encodedPayload += uriEncode(p.second) + "&";
    }

    if (!params.empty())
        encodedPayload.erase(encodedPayload.size() - 1);

    //cerr << "encodedPayload = " << encodedPayload << endl;

    result.payload = encodedPayload;
    
    addSignatureV4(result, serviceName, region, accessKeyId, accessKey,
                   date, digest);

    return result;

}

AwsBasicApi::BasicRequest
AwsBasicApi::
signGet(RestParams && params, const std::string & resource,
        Date date, PayloadDigest digest)
{
    BasicRequest result;
    result.method = "GET";
    result.relativeUri = resource;
    result.headers.push_back({"Host", serviceHost});
    result.queryParams = params;

    addSignatureV4(result, serviceName, region, accessKeyId, accessKey,
                   date, digest);

    return result;
}

std::unique_ptr<tinyxml2::XMLDocument>
AwsBasicApi::
performPost(RestParams && params,
            const std::string & resource,
            double timeoutSeconds,
            Date date, PayloadDigest digest)
{
    return perform(signPost(std::move(params), resource, date, digest),
                   timeoutSeconds, 3);
}

std::string
AwsBasicApi::
performPost(RestParams && params,
            const std::string & resource,
            const std::string & resultSelector,
            double timeoutSeconds,
            Date date,
            PayloadDigest digest)
{
    return extract<string>(*performPost(std::move(params), resource,
                                        timeoutSeconds, date, digest),
                           resultSelector);
}

std::unique_ptr<tinyxml2::XMLDocument>
AwsBasicApi::
performGet(RestParams && params,
           const std::string & resource,
           double timeoutSeconds,
           Date date,
           PayloadDigest digest)
{
    return perform(signGet(std::move(params), resource, date, digest),
                   timeoutSeconds, 3);
}

std::unique_ptr<tinyxml2::XMLDocument>
AwsBasicApi::
perform(const BasicRequest & request,
        double timeoutSeconds,
        int retries)
{
    int retry = 0;
    for (; retry < retries;  ++retry) {
        HttpRestProxy::Response response;
        try {
            response = proxy.perform(request.method,
                                     request.relativeUri,
                                     HttpRestProxy::Content(request.payload),
                                     request.queryParams,
                                     request.headers,
                                     timeoutSeconds);

            if (response.code() == 200) {
                std::unique_ptr<tinyxml2::XMLDocument> body(new tinyxml2::XMLDocument());
                body->Parse(response.body().c_str());
                return body;
            }
            else if (response.code() == 503)
                continue;
            else {
                cerr << "request failed: " << response << endl;
                break;
            }
        } catch (const std::exception & exc) {
            cerr << "error on request: " << exc.what() << endl;
        }
    }

    throw MLDB::Exception("failed request after %d retries", retries);
}

std::string
AwsBasicApi::
performGet(RestParams && params,
           const std::string & resource,
           const std::string & resultSelector,
           double timeoutSeconds,
           Date date,
           PayloadDigest digest)
{
    return extract<string>(*performGet(std::move(params), resource,
                                       timeoutSeconds, date, digest),
                           resultSelector);
}

} // namespace MLDB
