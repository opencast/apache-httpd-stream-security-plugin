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
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <errno.h>
#include "keys.h"

/*
 * Return the offset of the first newline in text or the length of
 * text if there's no newline.
 * @param text
 *      The text to check for the new line.
 */
int newline_offset(const char *text)
{
    const char *newline = strchr(text, '\n');
    if(!newline)
        return strlen(text);
    else
        return (int)(newline - text);
}

/**
 * Get a collection of keys from json text.
 * @param text
 *      The text to parse for the key ids and secrets.
 * @param secret_key_collection
 *      The KeyCollection to populate with the keys.
 */
void get_key_collection(char *text, struct KeyCollection *secret_key_collection)
{
    size_t i;

    json_t *root;
    json_error_t error;
    json_t *keys;

    if(!text) {
        secret_key_collection = NULL;
        return;
    }

    root = json_loads(text, 0, &error);
    free(text);

    if(!root)
    {
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        secret_key_collection = NULL;
        return;
    }

    keys = json_object_get(root, "keys");
    if(!json_is_array(keys))
    {
        fprintf(stderr, "error: keys is not an array\n");
        secret_key_collection = NULL;
        return;
    }

    if (json_array_size(keys) < 1) {
        fprintf(stderr, "There were no keys defined so nothing to secure. Make sure you define the necessary keys in your config file.\n");
        secret_key_collection = NULL;
        return;
    }

    secret_key_collection->secret_keys = (struct SecretKey *) malloc(sizeof(struct SecretKey) * json_array_size(keys));
    secret_key_collection->count = json_array_size(keys);
    struct SecretKey *secret_keys = secret_key_collection->secret_keys;

    for(i = 0; i < json_array_size(keys); i++)
    {
        json_t *key, *keyId, *secret;
        const char *secret_text;

        key = json_array_get(keys, i);
        if(!json_is_object(key))
        {
            fprintf(stderr, "error: key %zu is not an object\n", i + 1);
            secret_key_collection = NULL;
            return;
        }

        keyId = json_object_get(key, "id");
        if(!json_is_string(keyId))
        {
            fprintf(stderr, "error: key %zu: id is not a string\n", i + 1);
            secret_key_collection = NULL;
            return;
        }

        secret = json_object_get(key, "key");
        if(!json_is_string(secret))
        {
            fprintf(stderr, "error: key %zu: key is not a string\n", i + 1);
            secret_key_collection = NULL;
            return;
        }

        secret_text = json_string_value(secret);

        // Copy the values for the id and secret into the array.
        secret_keys[i].id = (char *)calloc(strlen(json_string_value(keyId)) + 1, sizeof(char));
        strcpy(secret_keys[i].id, json_string_value(keyId));

        // secret_keys[i].secret = (char *)malloc(sizeof(json_string_value(secret)));
        secret_keys[i].secret = (char *)calloc(strlen(json_string_value(secret)) + 1, sizeof(char));
        strcpy(secret_keys[i].secret, json_string_value(secret));
    }

    json_decref(root);
}

/**
 * Get the text from the security keys configuration file.
 */
char *get_stream_security_keys(const char *configPath)
{
    FILE *config_file;
    long lSize;
    char *buffer;

    config_file = fopen(configPath, "r");
    if (config_file == NULL) {
        printf("Unable to open file stream security configuration file '%s' because '%s'\n", configPath, strerror(errno));
        return NULL;
    }


    fseek( config_file , 0L , SEEK_END);
    lSize = ftell( config_file );
    rewind( config_file );

    /* allocate memory for entire content */
    buffer = calloc( 1, lSize+1 );
    if( !buffer ) fclose(config_file),fputs("memory alloc fails",stderr),exit(1);

    /* copy the file into the buffer */
    if( 1!=fread( buffer , lSize, 1 , config_file) )
    fclose(config_file),free(buffer),fputs("entire read fails",stderr),exit(1);

    fclose(config_file);
    return buffer;
}
