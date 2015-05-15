#ifndef URL_SIGNING_POLICY
#define URL_SIGNING_POLICY

/** The JSON keys for the policy. */
#define CONDITION_JSON_KEY  "Condition"
#define DATE_GREATER_THAN_JSON_KEY  "DateGreaterThan"
#define DATE_LESS_THAN_JSON_KEY  "DateLessThan"
#define IP_ADDRESS_JSON_KEY  "IpAddress"
#define RESOURCE_JSON_KEY  "Resource"
#define STATEMENT_JSON_KEY  "Statement"

struct Policy
{
    long long date_greater_than;
    long long date_less_than;
    char *ip_address;
    char *resource;
    char *decoded_policy;
};

/**
 * Sets the values of the current policy and returns an http response code for processing the policy.
 *
 * @param encodedPolicy
 *      The text to try to process into a Policy.
 * @param policy
 *      The provided policy whose values will be populated.
 * @return 200 (OK) is returned if everything went according to plan.
 **/
int get_policy_from_encoded_parameter(apr_pool_t *p, char* encodedPolicy, struct Policy *policy);
#endif
