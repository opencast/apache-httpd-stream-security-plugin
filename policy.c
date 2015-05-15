#include <jansson.h>

#include "base64.h"
#include "http.h"
#include "json_util.h"
#include "policy.h"

#include <string.h>

/**
 * Populate the data for a Policy from the decoded_policy member of the Policy.
 * @param policy
 *          The policy that has the decoded_policy and will be populated.
 * @return The HTTP response code.
 */
int get_policy_from_json(struct Policy *policy) {
    json_t *root;
    json_error_t error;
    json_t *statement;
    json_t *condition;

    char *policy_text = policy->decoded_policy;

    policy->date_less_than = -1;

    if(!policy_text) {
        return BAD_REQUEST;
    }

    root = json_loads(policy_text, 0, &error);

    if(!root)
    {
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        return BAD_REQUEST;
    }

    statement = json_object_get(root, STATEMENT_JSON_KEY);
    if(!json_is_object(statement))
    {
        fprintf(stderr, "error: %s is not an object\n", STATEMENT_JSON_KEY);
        return BAD_REQUEST;
    }

    condition = json_object_get(statement, CONDITION_JSON_KEY);
    if(!json_is_object(condition)) {
        fprintf(stderr, "error: %s is not an object\n", CONDITION_JSON_KEY);
        return BAD_REQUEST;
    }

    policy->ip_address = get_json_string(condition, IP_ADDRESS_JSON_KEY);

    policy->resource = get_json_string(statement, RESOURCE_JSON_KEY);
    if (policy->resource == NULL) {
        fprintf(stderr, "Unable to find json value of '%s'. Unable to authenticate response.\n", RESOURCE_JSON_KEY);
        return BAD_REQUEST;
    }

    policy->date_less_than = get_json_long_long(condition, DATE_LESS_THAN_JSON_KEY);
    if (policy->date_less_than < 0) {
        fprintf(stderr, "Unable to find the long value of %s\n", DATE_LESS_THAN_JSON_KEY);
        if (root) {
            printf("test");
        }
        return BAD_REQUEST;
    }

    policy->date_greater_than = get_json_long_long(condition, DATE_GREATER_THAN_JSON_KEY);
    return WORKING;
}

/**
 * Decode a policy from its base 64 encoding.
 * @param encodedPolicy
 *          The text of the base 64 encoded policy.
 * @return The plain text policy.
 */
char* decode_policy(char* encodedPolicy) {
    char* base64DecodeOutput;
    size_t length;
    base_64_decode(encodedPolicy, (uint8_t**)&base64DecodeOutput, &length);

    char *decodedPolicy = (char *) malloc(sizeof(char) * (length + 1));
    strncpy(decodedPolicy, base64DecodeOutput, length);
    decodedPolicy[length] = '\0';
    return decodedPolicy;
}

/**
 * Populate the data of a policy object from a Base 64 encoded json representation.
 * @param encodedPolicy
 *          The text representation of the json policy.
 * @param policy
 *          The policy object to populate.
 */
int get_policy_from_encoded_parameter(char* encodedPolicy, struct Policy *policy) {
    printf("Encoded Policy: '%s'\n", encodedPolicy);
    policy->decoded_policy = decode_policy(encodedPolicy);
    printf("Decoded Policy: '%s'\n", policy->decoded_policy);
    return get_policy_from_json(policy);
}

/**
 * Remove all of the allocated memory for a policy.
 * @param policy
 *          The policy to remove the memory from.
 */
void free_policy(struct Policy *policy) {
    if (policy->ip_address != NULL) {
        free(policy->ip_address);
    }
    free(policy->decoded_policy);
}
