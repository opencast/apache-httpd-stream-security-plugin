/**
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */
#include <jansson.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "httpd.h"
#include "apr_uri.h"

#include "keys.h"
#include "hmac.h"
#include "policy.h"
#include "resource_request.h"

static const int WORKING = -1;
static const char *IP_ADDRESS_DOESNT_MATCH = "The policy ip address doesn't match the client's ip address.";
static const char *KEY_NOT_FOUND = "The requested key could not be found.";
static const char *POLICY_SIGNATURE_WRONG = "The policy signature doesn't match the original signature.";
static const char *RESOURCE_DOESNT_MATCH = "The policy resource doesn't match the requested resource.";
static const char *NO_REASON = "";

struct QueryParameter
{
    char *key;
    char *value;
};

/**
 * Find the length of the key in the query string parameter.
 * @param inputString
 *          The query string parameter.
 */
int find_key_length(char* inputString) {
    int keyLength;
    for (keyLength = 0; keyLength < strlen(inputString); keyLength++) {
        if (inputString[keyLength] == '=') {
            return keyLength;
        }
    }
    return -1;
}

/**
 * Get the key and value of a query string parameter.
 * @param p
 *      The pool for this session that will be cleaned up after the request.
 * @param inputString
 *      The query string parameter.
 */
struct QueryParameter get_query_string_parameter(apr_pool_t *p, char* inputString) {
    apr_pool_t *mp;
    apr_pool_create(&mp, p);
    // Get the key.
    int keyLength = find_key_length(inputString);
    char *newKey = (char*) apr_pcalloc(mp, (keyLength + 1) * sizeof(char));
    strncpy(newKey, inputString, keyLength);
    newKey[keyLength] = '\0';

    // Get the value.
    int valueLength = strlen(inputString) - keyLength;
    char *newValue = (char*) apr_pcalloc(mp, (valueLength + 1) * sizeof(char));
    strncpy(newValue, inputString + keyLength + 1, valueLength);
    newValue[valueLength] = '\0';

    struct QueryParameter qp;
    qp.key = newKey;
    qp.value = newValue;
    return qp;
}

/**
 * Check that the user is authorized to get the resource from this request based on the policy.
 * @param clientIp
 *          The ip of the current client.
 * @param resourceUri
 *          The uri of the requested resource.
 * @param keyCollection
 *          The available keys configured.
 * @param resourceRequest
 *          The resource request to verify including the signature, keyid and policy.
 */
void verify_resource_request(apr_pool_t *p, int strict, char* clientIp, char* resourceUri, struct KeyCollection *keyCollection, struct ResourceRequest *resourceRequest) {
    time_t rawtime;
    time(&rawtime);
    long long unixEpoch = ((long long) rawtime) * 1000;

    int keyCount;
    char *key = NULL;
    bool foundKey = false;
    for(keyCount = 0; keyCount < keyCollection->count; keyCount++) {
        if (strcmp(resourceRequest->key_id, keyCollection->secret_keys[keyCount].id) == 0) {
            foundKey = true;
            key = keyCollection->secret_keys[keyCount].secret;
        }
    }

    if (!foundKey) {
        resourceRequest->status = HTTP_BAD_REQUEST;
        resourceRequest->reason = KEY_NOT_FOUND;
        return;
    }

    char *policy_signature = create_signature(p, key, resourceRequest->policy.decoded_policy);

    printf("Policy Signature is: '%s' Signature is '%s'\n", policy_signature, resourceRequest->signature);
    if (strcmp(policy_signature, resourceRequest->signature) != 0) {
        printf("The policy and signature doesn't match! %d\n", strcmp(policy_signature, resourceRequest->signature));
        resourceRequest->status = HTTP_FORBIDDEN;
        resourceRequest->reason = POLICY_SIGNATURE_WRONG;
        return;
    }

    if (strict && strcmp(resourceUri, resourceRequest->policy.resource) != 0) {
        printf("The resource requested and policy doesn't match! %s %s %d\n", resourceUri, resourceRequest->policy.resource, strcmp(resourceUri, resourceRequest->policy.resource));
        resourceRequest->status = HTTP_FORBIDDEN;
        resourceRequest->reason = RESOURCE_DOESNT_MATCH;
        return;
    } else if (!strict) {
        apr_pool_t *mp;
        apr_pool_create(&mp, p);
        apr_uri_t parsedURI;
        apr_uri_parse(mp, resourceRequest->policy.resource, &parsedURI);
        if (strcmp(resourceUri, parsedURI.path) != 0) {
            printf("The resource requested and policy path doesn't match! %s %s %s %d\n", resourceUri, parsedURI.path, resourceRequest->policy.resource, strcmp(parsedURI.path, resourceRequest->policy.resource));
            resourceRequest->status = HTTP_FORBIDDEN;
            resourceRequest->reason = "The path to the resource doesn't match";
            return;
        }
        apr_pool_destroy(mp);
    }

    struct Policy *policy = &resourceRequest->policy;

    if (policy->ip_address != NULL && strcmp(policy->ip_address, clientIp) != 0) {
        resourceRequest->status = HTTP_FORBIDDEN;
        resourceRequest->reason = IP_ADDRESS_DOESNT_MATCH;
        return;
    }

    // Make sure that the current time is before the expire time
    if (unixEpoch > policy->date_less_than) {
        resourceRequest->status = HTTP_GONE;
        return;
    }
    // Make sure that the current time is after the available time.
    if (policy->date_greater_than > 0 && unixEpoch < policy->date_greater_than) {
        resourceRequest->status = HTTP_GONE;
        return;
    }
    resourceRequest->status = HTTP_OK;
}

void get_resource_request_from_query_string(apr_pool_t *p, int strict, char* inputString, char* clientIp, char* resourceUri, struct KeyCollection *keyCollection, struct ResourceRequest *resourceRequest) {
    resourceRequest->key_id = NULL;
    resourceRequest->signature = NULL;
    resourceRequest->policy.ip_address = NULL;
    resourceRequest->policy.resource = NULL;
    resourceRequest->policy.decoded_policy = NULL;
    resourceRequest->reason = NO_REASON;

    if (inputString == NULL || strcmp("", inputString) == 0) {
        resourceRequest->status = HTTP_BAD_REQUEST;
        return;
    }

    char queryString[strlen(inputString)];
    strcpy(queryString, inputString);

    // Get the number of query string parameters.
    int tokenCount = 0;
    char *ch = strtok(queryString, "&");
    while (ch != NULL) {
        tokenCount++;
        ch = strtok(NULL, "&");
    }

    char* parameterPairs[tokenCount];
    strcpy(queryString, inputString);

    ch = strtok(queryString, "&");
    parameterPairs[0] = ch;
    int current = 0;
    while (ch != NULL) {
        ch = strtok(NULL, "&");
        current++;
        parameterPairs[current] = ch;
    }

    bool foundKey = false;
    bool foundPolicy = false;
    bool foundSignature = false;
    for (current = 0; current < tokenCount; current++) {
        struct QueryParameter qp = get_query_string_parameter(p, parameterPairs[current]);
        int result = WORKING;
        if (strcmp("policy", qp.key) == 0) {
            result = get_policy_from_encoded_parameter(p, qp.value, &resourceRequest->policy);
            printf("Result of Getting Policy: '%d' > '%lld' less '%" JSON_INTEGER_FORMAT "' ip '%s' resource '%s'\n", result, resourceRequest->policy.date_greater_than, resourceRequest->policy.date_less_than, resourceRequest->policy.ip_address, resourceRequest->policy.resource);
            foundPolicy = true;
        } else if (strcmp("keyId", qp.key) == 0) {
            resourceRequest->key_id = qp.value;
            printf("Got key id of '%s'\n", resourceRequest->key_id);
            foundKey = true;
        } else if (strcmp("signature", qp.key) == 0) {
            resourceRequest->signature = qp.value;
            printf("Got signature of '%s'\n", resourceRequest->signature);
            foundSignature = true;
        }
        if (result != WORKING) {
            fprintf(stderr, "Unable to process query string parameter '%s' with value '%s' had http result of %d\n", qp.key, qp.value, result);
            resourceRequest->status = result;
            return;
        }
    }
    // Check to make sure we got all of the necessary query string parameters.
    if (!foundKey || !foundPolicy || !foundSignature) {
        fprintf(stderr, "Unable to find all of the necessary query string parameters in request\n");
        resourceRequest->status = HTTP_BAD_REQUEST;
        return;
    }

    verify_resource_request(p, strict, clientIp, resourceUri, keyCollection, resourceRequest);
    printf("The status of the request is: %d\n", resourceRequest->status);
}
