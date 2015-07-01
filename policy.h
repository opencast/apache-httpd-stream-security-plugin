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
