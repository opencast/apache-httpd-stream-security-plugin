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
#include <openssl/hmac.h>
#include <string.h>
#include "base64.h"

static const int KEY_LENGTH = 32;

/**
 * Create a signed version of a policy based upon a shared secret.
 * @param p
 *          The pool to request memory from that will be cleaned on session close.
 * @param key
 *          The key to use as the secret to sign the policy.
 * @param policy
 *          The text to sign.
 * @param output
 *          The pointer to assign the signed policy.
 */
char *create_signature(apr_pool_t *p, char* key, char* policy, char** output) {
    unsigned char* digest;
    digest = HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)policy, strlen(policy), NULL, NULL);

    char hmacString[KEY_LENGTH];
    int i;
    for(i = 0; i < KEY_LENGTH; i++)
         sprintf(&hmacString[i*2], "%02x", (unsigned int)digest[i]);

    int size = strlen(hmacString) * sizeof(char) + 1;
    char *hmac = (char *)apr_palloc(p, size);
    strcpy(hmac, hmacString);
    return hmac;
}
