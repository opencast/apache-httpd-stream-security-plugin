/*
 * Copyright (c) 2009-2011 Petri Lehtinen <petri@digip.org>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <assert.h>

#include "base64.h"
#include "http.h"
#include "keys.h"
#include "policy.h"
#include "resource_request.h"

struct KeyCollection secret_key_collection;

int main(int argc, char *argv[])
{
    const char *testKeys = "stream-security-keys.json";
    char *text = get_stream_security_keys(testKeys);
    printf("Got secret keys json: \n%s", text);
    struct KeyCollection secret_key_collection;
    get_key_collection(text, &secret_key_collection);
    printf("Secret key collection has %d keys.\n", secret_key_collection.count);

    char *clientIp = "10.0.0.1";
    char *resourceUri = "rtmp://mh-wowza.localdomain/matterhorn-engage/flv:engage-player/e9362052-20a7-45e3-a64e-7480f65fa42b/fac8d2bf-d655-41a7-885a-6318ca82fd23/composite_with_sound";

    printf("\n");
    printf("|------------|\n");
    printf("| Testing OK |\n");
    printf("|------------|\n");
    char *ok = "policy=eyJTdGF0ZW1lbnQiOnsiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6MTUyNjE5OTgwNzUzOH0sIlJlc291cmNlIjoicnRtcDpcL1wvbWgtd293emEubG9jYWxkb21haW5cL21hdHRlcmhvcm4tZW5nYWdlXC9mbHY6ZW5nYWdlLXBsYXllclwvZTkzNjIwNTItMjBhNy00NWUzLWE2NGUtNzQ4MGY2NWZhNDJiXC9mYWM4ZDJiZi1kNjU1LTQxYTctODg1YS02MzE4Y2E4MmZkMjNcL2NvbXBvc2l0ZV93aXRoX3NvdW5kIn19&keyId=theId&signature=1af498df6069ca3652102c258d7bcc4974f26d71f9467abce47c04d02bef4df6";
    struct ResourceRequest okResult;
    get_resource_request_from_query_string(ok, clientIp, resourceUri, &secret_key_collection, &okResult);
    assert(okResult.status == OK);
    free_resource_request(&okResult);

    // -----------------------
    // Test Missing Parameters
    // -----------------------

    printf("\n");
    printf("|------------------------|\n");
    printf("| Testing Missing Key Id |\n");
    printf("|------------------------|\n");
    char *missingKeyId = "policy=eyJTdGF0ZW1lbnQiOnsiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6MTUyNjE5OTgwNzUzOH0sIlJlc291cmNlIjoicnRtcDpcL1wvbWgtd293emEubG9jYWxkb21haW5cL21hdHRlcmhvcm4tZW5nYWdlXC9mbHY6ZW5nYWdlLXBsYXllclwvZTkzNjIwNTItMjBhNy00NWUzLWE2NGUtNzQ4MGY2NWZhNDJiXC9mYWM4ZDJiZi1kNjU1LTQxYTctODg1YS02MzE4Y2E4MmZkMjNcL2NvbXBvc2l0ZV93aXRoX3NvdW5kIn19&signature=1af498df6069ca3652102c258d7bcc4974f26d71f9467abce47c04d02bef4df6";
    struct ResourceRequest missingKeyIdResult;
    get_resource_request_from_query_string(missingKeyId, clientIp, resourceUri, &secret_key_collection, &missingKeyIdResult);
    assert(missingKeyIdResult.status == BAD_REQUEST);
    free_resource_request(&missingKeyIdResult);

    printf("\n");
    printf("// -----------------------|\n");
    printf("// Testing Missing Policy |\n");
    printf("// -----------------------|\n");
    char *missingPolicy = "keyId=theId&signature=1af498df6069ca3652102c258d7bcc4974f26d71f9467abce47c04d02bef4df6";
    struct ResourceRequest missingPolicyResult;
    get_resource_request_from_query_string(missingPolicy, clientIp, resourceUri, &secret_key_collection, &missingPolicyResult);
    assert(missingPolicyResult.status == BAD_REQUEST);
    free_resource_request(&missingPolicyResult);

    printf("\n");
    printf("|---------------------------|\n");
    printf("| Testing Missing Signature |\n");
    printf("|---------------------------|\n");
    char *missingSignature = "policy=eyJTdGF0ZW1lbnQiOnsiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6MTUyNjE5OTgwNzUzOH0sIlJlc291cmNlIjoicnRtcDpcL1wvbWgtd293emEubG9jYWxkb21haW5cL21hdHRlcmhvcm4tZW5nYWdlXC9mbHY6ZW5nYWdlLXBsYXllclwvZTkzNjIwNTItMjBhNy00NWUzLWE2NGUtNzQ4MGY2NWZhNDJiXC9mYWM4ZDJiZi1kNjU1LTQxYTctODg1YS02MzE4Y2E4MmZkMjNcL2NvbXBvc2l0ZV93aXRoX3NvdW5kIn19&keyId=theId";
    struct ResourceRequest missingSignatureResult;
    get_resource_request_from_query_string(missingSignature, clientIp, resourceUri, &secret_key_collection, &missingSignatureResult);
    assert(missingSignatureResult.status == BAD_REQUEST);
    free_resource_request(&missingSignatureResult);

    // ----------------------------
    // Testing Expired or Too Early
    // ----------------------------
    printf("\n");
    printf("|---------------------------|\n");
    printf("| Testing Policy Expired    |\n");
    printf("|---------------------------|\n");
    char *policyExpired = "policy=eyJTdGF0ZW1lbnQiOnsiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6MTMyNjE5OTgwNzUzOH0sIlJlc291cmNlIjoicnRtcDpcL1wvbWgtd293emEubG9jYWxkb21haW5cL21hdHRlcmhvcm4tZW5nYWdlXC9mbHY6ZW5nYWdlLXBsYXllclwvZTkzNjIwNTItMjBhNy00NWUzLWE2NGUtNzQ4MGY2NWZhNDJiXC9mYWM4ZDJiZi1kNjU1LTQxYTctODg1YS02MzE4Y2E4MmZkMjNcL2NvbXBvc2l0ZV93aXRoX3NvdW5kIn19&keyId=theId&signature=c9163b8733944afc381840dae964007b95ef3b56fc1ab224e81c047d3bee2b7b";
    struct ResourceRequest policyExpiredResult;
    get_resource_request_from_query_string(policyExpired, clientIp, resourceUri, &secret_key_collection, &policyExpiredResult);
    assert(policyExpiredResult.status == GONE);
    free_resource_request(&policyExpiredResult);

    printf("\n");
    printf("|-------------------|\n");
    printf("| Testing Too Early |\n");
    printf("|-------------------|\n");
    char *tooEarly = "policy=eyJTdGF0ZW1lbnQiOnsiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6MTgyNjE5OTgwNzUzOCwiRGF0ZUdyZWF0ZXJUaGFuIjoxODI1MDg0Mzc5MDAwfSwiUmVzb3VyY2UiOiJydG1wOlwvXC9taC13b3d6YS5sb2NhbGRvbWFpblwvbWF0dGVyaG9ybi1lbmdhZ2VcL2ZsdjplbmdhZ2UtcGxheWVyXC9lOTM2MjA1Mi0yMGE3LTQ1ZTMtYTY0ZS03NDgwZjY1ZmE0MmJcL2ZhYzhkMmJmLWQ2NTUtNDFhNy04ODVhLTYzMThjYTgyZmQyM1wvY29tcG9zaXRlX3dpdGhfc291bmQifX0=&keyId=theId&signature=88deb6a8a303bc0c2424067587832793a405407595d670a9144bb6243d049d40";
    struct ResourceRequest tooEarlyResult;
    get_resource_request_from_query_string(tooEarly, clientIp, resourceUri, &secret_key_collection, &tooEarlyResult);
    assert(policyExpiredResult.status == GONE);
    free_resource_request(&tooEarlyResult);

    // -------------------------------
    // Testing Failure to Authenticate
    // -------------------------------
    printf("\n");
    printf("|--------------------------------|\n");
    printf("| Testing Non Matching Signature |\n");
    printf("|--------------------------------|\n");
     char *wrongSignature = "policy=eyJTdGF0ZW1lbnQiOnsiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6MTUyNjE5OTgwNzUzOH0sIlJlc291cmNlIjoicnRtcDpcL1wvbWgtd293emEubG9jYWxkb21haW5cL21hdHRlcmhvcm4tZW5nYWdlXC9mbHY6ZW5nYWdlLXBsYXllclwvZTkzNjIwNTItMjBhNy00NWUzLWE2NGUtNzQ4MGY2NWZhNDJiXC9mYWM4ZDJiZi1kNjU1LTQxYTctODg1YS02MzE4Y2E4MmZkMjNcL2NvbXBvc2l0ZV93aXRoX3NvdW5kIn19&keyId=theId&signature=nonmatching";
    struct ResourceRequest wrongSignatureResult;
    get_resource_request_from_query_string(wrongSignature, clientIp, resourceUri, &secret_key_collection, &wrongSignatureResult);
    assert(wrongSignatureResult.status == FORBIDDEN);
    free_resource_request(&wrongSignatureResult);

    printf("\n");
    printf("|--------------------------------|\n");
    printf("| Testing Non Matching Client IP |\n");
    printf("|--------------------------------|\n");
    char *wrongIp = "policy=eyJTdGF0ZW1lbnQiOnsiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6MTgyNjE5OTgwNzUzOCwgIklwQWRkcmVzcyI6ICIxMC4wLjAuMSJ9LCJSZXNvdXJjZSI6InJ0bXA6XC9cL21oLXdvd3phLmxvY2FsZG9tYWluXC9tYXR0ZXJob3JuLWVuZ2FnZVwvZmx2OmVuZ2FnZS1wbGF5ZXJcL2U5MzYyMDUyLTIwYTctNDVlMy1hNjRlLTc0ODBmNjVmYTQyYlwvZmFjOGQyYmYtZDY1NS00MWE3LTg4NWEtNjMxOGNhODJmZDIzXC9jb21wb3NpdGVfd2l0aF9zb3VuZCJ9fQ==&keyId=theId&signature=ae13a4acece414e4cbd4e9ef28030673be531553ae7e8f8c02091e76facd4442";
    struct ResourceRequest wrongIpResult;
    get_resource_request_from_query_string(wrongIp, clientIp, resourceUri, &secret_key_collection, &wrongIpResult);
    assert(wrongSignatureResult.status == FORBIDDEN);
    free_resource_request(&wrongIpResult);

    printf("\n");
    printf("|-------------------------------|\n");
    printf("| Testing Non Matching Resource |\n");
    printf("|-------------------------------|\n");
    char *wrongResource = "policy=eyJTdGF0ZW1lbnQiOnsiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6MTUyNjE5OTgwNzUzOH0sIlJlc291cmNlIjoicnRtcDpcL1wvbWgtd293emEubG9jYWxkb21haW5cL21hdHRlcmhvcm4tZW5nYWdlXC9mbHY6ZW5nYWdlLXBsYXllclwvZTkzNjIwNTItMjBhNy00NWUzLWE2NGUtNzQ4MGY2NWZhNDJiXC9mYWM4ZDJiZi1kNjU1LTQxYTctODg1YS02MzE4Y2E4MmZkMjNcL290aGVyIn19&keyId=theId&signature=dc9696371b222d8711ea0286d0864e9125900edc944ed09258bf98ea9a421fb7";
    struct ResourceRequest wrongResourceResult;
    get_resource_request_from_query_string(wrongResource, clientIp, resourceUri, &secret_key_collection, &wrongResourceResult);
    assert(wrongResourceResult.status == FORBIDDEN);
    free_resource_request(&wrongResourceResult);

    printf("\n");
    printf("|--------------------|\n");
    printf("| Testing Bad Key ID |\n");
    printf("|--------------------|\n");
    char *badKey = "policy=eyJTdGF0ZW1lbnQiOnsiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6MTUyNjE5OTgwNzUzOH0sIlJlc291cmNlIjoicnRtcDpcL1wvbWgtd293emEubG9jYWxkb21haW5cL21hdHRlcmhvcm4tZW5nYWdlXC9mbHY6ZW5nYWdlLXBsYXllclwvZTkzNjIwNTItMjBhNy00NWUzLWE2NGUtNzQ4MGY2NWZhNDJiXC9mYWM4ZDJiZi1kNjU1LTQxYTctODg1YS02MzE4Y2E4MmZkMjNcL2NvbXBvc2l0ZV93aXRoX3NvdW5kIn19&keyId=wrongKey&signature=1af498df6069ca3652102c258d7bcc4974f26d71f9467abce47c04d02bef4df6";
    struct ResourceRequest badKeyResult;
    get_resource_request_from_query_string(badKey, clientIp, resourceUri, &secret_key_collection, &badKeyResult);
    assert(badKeyResult.status == BAD_REQUEST);
    free_resource_request(&badKeyResult);


    printf("\n");
    printf("|----------------------------|\n");
    printf("| Testing Empty Query String |\n");
    printf("|----------------------------|\n");
    char *emptyQueryString = "";
    struct ResourceRequest emptyQueryStringResult;
    get_resource_request_from_query_string(emptyQueryString, clientIp, resourceUri, &secret_key_collection, &emptyQueryStringResult);
    assert(badKeyResult.status == BAD_REQUEST);
    free_resource_request(&emptyQueryStringResult);

    printf("\n");
    printf("|---------------------------|\n");
    printf("| Testing NULL Query String |\n");
    printf("|---------------------------|\n");
    char *nullQueryString = NULL;
    struct ResourceRequest nullQueryStringResult;
    get_resource_request_from_query_string(nullQueryString, clientIp, resourceUri, &secret_key_collection, &nullQueryStringResult);
    assert(badKeyResult.status == BAD_REQUEST);
    free_resource_request(&nullQueryStringResult);

    return 0;
}
