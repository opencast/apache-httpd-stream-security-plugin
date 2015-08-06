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
#include <stdlib.h>
#include <string.h>
#include "json_util.h"
#include "httpd.h"

/**
 * Gets a json string value.
 * @param parent
 *      The json object who is a parent to this key : string value pair.
 * @param json_key
 *      The string key that will identify the value to retrieve.
 * @return The string value if available, NULL if not.
 */
char *get_json_string(apr_pool_t *p, json_t *parent, char *json_key) {
    json_t *obj = json_object_get(parent, json_key);

    if(!json_is_string(obj)) {
        return NULL;
    } else {
        char *return_string = (char *)apr_pcalloc(p, strlen(json_string_value(obj)) * sizeof(char) + 1);
        strcpy(return_string, json_string_value(obj));
        return return_string;
    }
}

/**
 * Gets a json integer value.
 * @param parent
 *          The json object who is a parent to this key : integer value pair.
 * @param json_key
 *          The string that will identify the integer to retrieve.
 */
long long get_json_long_long(json_t *parent, char *json_key) {
    json_t *value = json_object_get(parent, json_key);
    if(!json_is_integer(value)) {
        return -1;
    } else {
        return (long long)json_integer_value(value);
    }
}

