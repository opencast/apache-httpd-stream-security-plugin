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
        char *return_string = (char *)apr_palloc(p, strlen(json_string_value(obj)) * sizeof(char) + 1);
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

