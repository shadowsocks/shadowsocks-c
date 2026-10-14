// SPDX-License-Identifier: GPL-3.0-or-later
// JSON parser (src/json.cpp): values, nesting and malformed input.
#include <cstdint>
#include <cstring>

#include "json.h"
#include "test_helpers.hpp"

namespace {

json_value *parse(const char *text)
{
    return json_parse(text, std::strlen(text));
}

void test_parse_simple_object()
{
    json_value *val = parse("{\"key\": \"value\", \"num\": 42}");
    SS_CHECK(val != nullptr);
    SS_CHECK(val->type == json_object);
    SS_CHECK(val->u.object.length == 2);

    // First entry.
    SS_CHECK(std::strcmp(val->u.object.values[0].name, "key") == 0);
    SS_CHECK(val->u.object.values[0].value->type == json_string);
    SS_CHECK(std::strcmp(val->u.object.values[0].value->u.string.ptr, "value") == 0);

    // Second entry.
    SS_CHECK(std::strcmp(val->u.object.values[1].name, "num") == 0);
    SS_CHECK(val->u.object.values[1].value->type == json_integer);
    SS_CHECK(val->u.object.values[1].value->u.integer == 42);

    json_value_free(val);
}

void test_parse_array()
{
    json_value *val = parse("[1, 2, 3]");
    SS_CHECK(val != nullptr);
    SS_CHECK(val->type == json_array);
    SS_CHECK(val->u.array.length == 3);
    SS_CHECK(val->u.array.values[0]->type == json_integer);
    SS_CHECK(val->u.array.values[0]->u.integer == 1);
    SS_CHECK(val->u.array.values[1]->u.integer == 2);
    SS_CHECK(val->u.array.values[2]->u.integer == 3);

    json_value_free(val);
}

void test_parse_nested()
{
    json_value *val = parse("{\"outer\": {\"inner\": true}}");
    SS_CHECK(val != nullptr);
    SS_CHECK(val->type == json_object);
    SS_CHECK(val->u.object.length == 1);

    json_value *outer = val->u.object.values[0].value;
    SS_CHECK(outer->type == json_object);
    SS_CHECK(outer->u.object.length == 1);

    SS_CHECK(outer->u.object.values[0].value->type == json_boolean);
    SS_CHECK(outer->u.object.values[0].value->u.boolean != 0);

    json_value_free(val);
}

void test_parse_types()
{
    json_value *val = parse("{\"s\": \"hello\", \"i\": -5, \"d\": 3.14, \"b\": false, \"n\": null}");
    SS_CHECK(val != nullptr);
    SS_CHECK(val->type == json_object);
    SS_CHECK(val->u.object.length == 5);

    SS_CHECK(val->u.object.values[0].value->type == json_string);
    SS_CHECK(val->u.object.values[1].value->type == json_integer);
    SS_CHECK(val->u.object.values[1].value->u.integer == -5);
    SS_CHECK(val->u.object.values[2].value->type == json_double);
    SS_CHECK(val->u.object.values[3].value->type == json_boolean);
    SS_CHECK(val->u.object.values[3].value->u.boolean == 0);
    SS_CHECK(val->u.object.values[4].value->type == json_null);

    json_value_free(val);
}

void test_parse_invalid()
{
    // Missing closing brace.
    SS_CHECK(json_parse("{\"key\": 1", 9) == nullptr);

    // Empty string.
    SS_CHECK(json_parse("", 0) == nullptr);

    // Just garbage.
    SS_CHECK(json_parse("not json", 8) == nullptr);
}

void test_parse_truncated_escape_sequences()
{
    // Four bytes remain after 'u', but the fourth hex read would hit EOF.
    SS_CHECK(parse("\"\\uB2D") == nullptr);

    // Six bytes remain after the high surrogate, but the sixth read would hit EOF.
    SS_CHECK(parse("\"\\udfff\\ufff") == nullptr);
}

void test_parse_truncated_literals()
{
    SS_CHECK(json_parse("tru", 3) == nullptr);
    SS_CHECK(json_parse("fals", 4) == nullptr);
    SS_CHECK(json_parse("nul", 3) == nullptr);
}

void test_parse_empty_object()
{
    json_value *val = parse("{}");
    SS_CHECK(val != nullptr);
    SS_CHECK(val->type == json_object);
    SS_CHECK(val->u.object.length == 0);
    json_value_free(val);
}

void test_parse_empty_array()
{
    json_value *val = parse("[]");
    SS_CHECK(val != nullptr);
    SS_CHECK(val->type == json_array);
    SS_CHECK(val->u.array.length == 0);
    json_value_free(val);
}

void test_parse_wide_numbers()
{
    json_value *wide = parse("[4294967296,9223372036854775807,-4294967296,0.4294967296]");
    SS_CHECK(wide != nullptr && wide->type == json_array && wide->u.array.length == 4);
    SS_CHECK(wide->u.array.values[0]->u.integer == INT64_C(4294967296));
    SS_CHECK(wide->u.array.values[1]->u.integer == INT64_MAX);
    SS_CHECK(wide->u.array.values[2]->u.integer == -INT64_C(4294967296));
    SS_CHECK(wide->u.array.values[3]->u.dbl > 0.4294967295 && wide->u.array.values[3]->u.dbl < 0.4294967297);
    json_value_free(wide);
    SS_CHECK(json_parse("9223372036854775808", 19) == nullptr);
}

} // namespace

int main()
{
    SS_RUN(test_parse_wide_numbers);
    SS_RUN(test_parse_simple_object);
    SS_RUN(test_parse_array);
    SS_RUN(test_parse_nested);
    SS_RUN(test_parse_types);
    SS_RUN(test_parse_invalid);
    SS_RUN(test_parse_truncated_escape_sequences);
    SS_RUN(test_parse_truncated_literals);
    SS_RUN(test_parse_empty_object);
    SS_RUN(test_parse_empty_array);
    return 0;
}
