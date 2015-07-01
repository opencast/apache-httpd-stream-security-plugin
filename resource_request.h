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
#ifndef URL_SIGNING_RESOURCE_REQUEST
#define URL_SIGNING_RESOURCE_REQUEST

#include "keys.h"
#include "policy.h"

struct ResourceRequest
{
    int status;
    const char *reason;
    struct Policy policy;
    char *signature;
    char *key_id;
};

void get_resource_request_from_query_string(apr_pool_t *p, char* queryString, char* clientIp, char* resourceUri, struct KeyCollection *keyCollection, struct ResourceRequest *resourceRequest);
#endif
