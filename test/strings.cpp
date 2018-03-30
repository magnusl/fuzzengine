#include <gtest\gtest.h>
#include <fuzzengine\bytecode.h>
#include <fuzzengine\generator.h>
#include <sstream>

using namespace fuzzer::parser;
using namespace fuzzer::bytecode;

TEST(Strings, EscapedNewLine)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { var x = \"\\n\"; }";
    fuzzer::parser::Tokenizer token(str);
    EXPECT_NO_THROW(generator.ParseScript(token));
}

TEST(Strings, EscapedCarriageReturn)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { var x = \"\\r\"; }";
    fuzzer::parser::Tokenizer token(str);
    EXPECT_NO_THROW(generator.ParseScript(token));
}

TEST(Strings, EscapedTab)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { var x = \"\\t\"; }";
    fuzzer::parser::Tokenizer token(str);
    EXPECT_NO_THROW(generator.ParseScript(token));
}

TEST(Strings, EscapedBackslash)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { var x = \"\\\\\"; }";
    fuzzer::parser::Tokenizer token(str);
    EXPECT_NO_THROW(generator.ParseScript(token));
}