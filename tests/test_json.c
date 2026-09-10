#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "json.h"

static void
test_parse_simple_object(void)
{
    const char *json_str = "{\"key\": \"value\", \"num\": 42}";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_object);
    assert(val->u.object.length == 2);

    /* Check first entry */
    assert(strcmp(val->u.object.values[0].name, "key") == 0);
    assert(val->u.object.values[0].value->type == json_string);
    assert(strcmp(val->u.object.values[0].value->u.string.ptr, "value") == 0);

    /* Check second entry */
    assert(strcmp(val->u.object.values[1].name, "num") == 0);
    assert(val->u.object.values[1].value->type == json_integer);
    assert(val->u.object.values[1].value->u.integer == 42);

    json_value_free(val);
}

static void
test_parse_array(void)
{
    const char *json_str = "[1, 2, 3]";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_array);
    assert(val->u.array.length == 3);
    assert(val->u.array.values[0]->type == json_integer);
    assert(val->u.array.values[0]->u.integer == 1);
    assert(val->u.array.values[1]->u.integer == 2);
    assert(val->u.array.values[2]->u.integer == 3);

    json_value_free(val);
}

static void
test_parse_nested(void)
{
    const char *json_str = "{\"outer\": {\"inner\": true}}";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_object);
    assert(val->u.object.length == 1);

    json_value *outer = val->u.object.values[0].value;
    assert(outer->type == json_object);
    assert(outer->u.object.length == 1);

    assert(outer->u.object.values[0].value->type == json_boolean);
    assert(outer->u.object.values[0].value->u.boolean != 0);

    json_value_free(val);
}

static void
test_parse_types(void)
{
    const char *json_str = "{\"s\": \"hello\", \"i\": -5, \"d\": 3.14, \"b\": false, \"n\": null}";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_object);
    assert(val->u.object.length == 5);

    assert(val->u.object.values[0].value->type == json_string);
    assert(val->u.object.values[1].value->type == json_integer);
    assert(val->u.object.values[1].value->u.integer == -5);
    assert(val->u.object.values[2].value->type == json_double);
    assert(val->u.object.values[3].value->type == json_boolean);
    assert(val->u.object.values[3].value->u.boolean == 0);
    assert(val->u.object.values[4].value->type == json_null);

    json_value_free(val);
}

static void
test_parse_invalid(void)
{
    /* Missing closing brace */
    assert(json_parse("{\"key\": 1", 9) == NULL);

    /* Empty string */
    assert(json_parse("", 0) == NULL);

    /* Just garbage */
    assert(json_parse("not json", 8) == NULL);
}

static void
test_parse_truncated_escape_sequences(void)
{
    /* Four bytes remain after 'u', but the fourth hex read would hit EOF. */
    const char *truncated_unicode_escape = "\"\\uB2D";
    assert(json_parse(truncated_unicode_escape, strlen(truncated_unicode_escape)) == NULL);

    /* Six bytes remain after the high surrogate, but the sixth read would hit EOF. */
    const char *truncated_surrogate_pair = "\"\\udfff\\ufff";
    assert(json_parse(truncated_surrogate_pair, strlen(truncated_surrogate_pair)) == NULL);
}

static void
test_parse_truncated_literals(void)
{
    assert(json_parse("tru", 3) == NULL);
    assert(json_parse("fals", 4) == NULL);
    assert(json_parse("nul", 3) == NULL);
}

static void
test_parse_empty_object(void)
{
    const char *json_str = "{}";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_object);
    assert(val->u.object.length == 0);
    json_value_free(val);
}

static void
test_parse_empty_array(void)
{
    const char *json_str = "[]";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_array);
    assert(val->u.array.length == 0);
    json_value_free(val);
}

int
main(void)
{
    const char *wide_numbers = "[4294967296,9223372036854775807,-4294967296,0.4294967296]";
    json_value *wide = json_parse(wide_numbers, strlen(wide_numbers));
    assert(wide != NULL && wide->type == json_array && wide->u.array.length == 4);
    assert(wide->u.array.values[0]->u.integer == INT64_C(4294967296));
    assert(wide->u.array.values[1]->u.integer == INT64_MAX);
    assert(wide->u.array.values[2]->u.integer == -INT64_C(4294967296));
    assert(wide->u.array.values[3]->u.dbl > 0.4294967295 && wide->u.array.values[3]->u.dbl < 0.4294967297);
    json_value_free(wide);
    assert(json_parse("9223372036854775808", 19) == NULL);
    test_parse_simple_object();
    test_parse_array();
    test_parse_nested();
    test_parse_types();
    test_parse_invalid();
    test_parse_truncated_escape_sequences();
    test_parse_truncated_literals();
    test_parse_empty_object();
    test_parse_empty_array();
    return 0;
}
