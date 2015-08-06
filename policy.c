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
#include "httpd.h"

#include "base64.h"
#include "json_util.h"
#include "policy.h"

#include <string.h>

/**
 * Populate the data for a Policy from the decoded_policy member of the Policy.
 * @param policy
 *          The policy that has the decoded_policy and will be populated.
 * @return The HTTP response code.
 */
int get_policy_from_json(apr_pool_t *p, struct Policy *policy) {
    json_t *root;
    json_error_t error;
    json_t *statement;
    json_t *condition;

    char *policy_text = policy->decoded_policy;

    policy->date_less_than = -1;

    if(!policy_text || strcmp(policy_text, "") == 0) {
        fprintf(stderr, "No policy text provided.\n");
        return HTTP_BAD_REQUEST;
    }

    root = json_loads(policy_text, 0, &error);

    if(!root)
    {
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        return HTTP_BAD_REQUEST;
    }

    statement = json_object_get(root, STATEMENT_JSON_KEY);
    if(!json_is_object(statement))
    {
        fprintf(stderr, "error: %s is not an object\n", STATEMENT_JSON_KEY);
        return HTTP_BAD_REQUEST;
    }

    condition = json_object_get(statement, CONDITION_JSON_KEY);
    if(!json_is_object(condition)) {
        fprintf(stderr, "error: %s is not an object\n", CONDITION_JSON_KEY);
        return HTTP_BAD_REQUEST;
    }

    policy->ip_address = get_json_string(p, condition, IP_ADDRESS_JSON_KEY);

    policy->resource = get_json_string(p, statement, RESOURCE_JSON_KEY);
    if (policy->resource == NULL) {
        fprintf(stderr, "Unable to find json value of '%s'. Unable to authenticate response.\n", RESOURCE_JSON_KEY);
        return HTTP_BAD_REQUEST;
    }

    policy->date_less_than = get_json_long_long(condition, DATE_LESS_THAN_JSON_KEY);
    if (policy->date_less_than < 0) {
        fprintf(stderr, "Unable to find the long value of %s\n", DATE_LESS_THAN_JSON_KEY);
        if (root) {
            printf("test");
        }
        return HTTP_BAD_REQUEST;
    }

    policy->date_greater_than = get_json_long_long(condition, DATE_GREATER_THAN_JSON_KEY);
    return -1;
}

/**
 * Decode a policy from its base 64 encoding.
 * @param encodedPolicy
 *          The text of the base 64 encoded policy.
 * @return The plain text policy.
 */
int decode_policy(apr_pool_t *p, char* encodedPolicy, char** decodedPolicyPtr) {
    char* base64DecodeOutput;
    size_t length;
    int base64Result = base_64_decode(p, encodedPolicy, (uint8_t**)&base64DecodeOutput, &length);
    if (base64Result != 0) {
        return base64Result;
    }
    char *decodedPolicy = (char *) apr_pcalloc(p, sizeof(char) * (length + 1));
    strncpy(decodedPolicy, base64DecodeOutput, length);
    decodedPolicy[length] = '\0';

    *decodedPolicyPtr = decodedPolicy;

    return 0;
}

/**
 * Populate the data of a policy object from a Base 64 encoded json representation.
 * @param encodedPolicy
 *          The text representation of the json policy.
 * @param policy
 *          The policy object to populate.
 */
int get_policy_from_encoded_parameter(apr_pool_t *p, char* encodedPolicy, struct Policy *policy) {
    if(!encodedPolicy || strcmp(encodedPolicy, "") == 0) {
        fprintf(stderr, "No policy text provided.\n");
        return HTTP_BAD_REQUEST;
    }
    printf("Encoded Policy: '%s'\n", encodedPolicy);
    int decodePolicyResult = decode_policy(p, encodedPolicy, &policy->decoded_policy);
    if (decodePolicyResult != 0) {
        return decodePolicyResult;
    }
    printf("Decoded Policy: '%s'\n", policy->decoded_policy);
    return get_policy_from_json(p, policy);
}
