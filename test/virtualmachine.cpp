#include <gtest\gtest.h>
#include <fuzzengine\bytecode.h>
#include <fuzzengine\generator.h>
#include <fuzzengine\vm.h>
#include <sstream>

using namespace fuzzer::parser;
using namespace fuzzer::bytecode;

TEST(VirtualMachine, ReturnConstant)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { return 1;}";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];

    fuzzer::bytecode::VirtualMachine vm;
    fuzzer::bytecode::Value result;
    
    EXPECT_NO_THROW(result = vm.Execute(*script, *method));
    EXPECT_EQ(fuzzer::bytecode::Value::INT, result.type);
    EXPECT_EQ(1, result.u.uValue);
}

TEST(VirtualMachine, ReturnConstantString)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { return \"Hello World\";}";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];

    fuzzer::bytecode::VirtualMachine vm;
    fuzzer::bytecode::Value result;
    
    ASSERT_NO_THROW(result = vm.Execute(*script, *method));
    EXPECT_EQ(fuzzer::bytecode::Value::STRING, result.type);
    ASSERT_FALSE( !result.stringValue );
    EXPECT_STREQ("Hello World", result.stringValue->c_str());
}

TEST(VirtualMachine, ReturnConstantAdd)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { return 1 + 2;}";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];

    fuzzer::bytecode::VirtualMachine vm;
    fuzzer::bytecode::Value result;
    
    EXPECT_NO_THROW(result = vm.Execute(*script, *method));
    EXPECT_EQ(fuzzer::bytecode::Value::INT, result.type);
    EXPECT_EQ(3, result.u.uValue);
}

///////////////////////////////////////////////////////////////////////////////
//                                  Method calls                             //
///////////////////////////////////////////////////////////////////////////////
TEST(VirtualMachine, CallAndReturn)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function calle()    { return 1337; }";
    str << "function caller()   { return calle() + 1;}";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(2, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> caller = script->_methods[1];

    fuzzer::bytecode::VirtualMachine vm;
    fuzzer::bytecode::Value result;
    
    EXPECT_NO_THROW(result = vm.Execute(*script, *caller));
    EXPECT_EQ(fuzzer::bytecode::Value::INT, result.type);
    EXPECT_EQ(1338, result.u.uValue);
}

TEST(VirtualMachine, ReturnResultFromTwoCalls)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function calle()    { return 1337; }";
    str << "function caller()   { return calle() + calle();}";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(2, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> caller = script->_methods[1];

    fuzzer::bytecode::VirtualMachine vm;
    fuzzer::bytecode::Value result;
    
    EXPECT_NO_THROW(result = vm.Execute(*script, *caller));
    EXPECT_EQ(fuzzer::bytecode::Value::INT, result.type);
    EXPECT_EQ(1337 + 1337, result.u.uValue);
}

TEST(VirtualMachine, CallWithArgument)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function calle(x)   { return x + 1000; }";
    str << "function caller()   { return calle(50); }";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(2, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> caller = script->_methods[1];

    fuzzer::bytecode::VirtualMachine vm;
    fuzzer::bytecode::Value result;
    
    EXPECT_NO_THROW(result = vm.Execute(*script, *caller));
    EXPECT_EQ(fuzzer::bytecode::Value::INT, result.type);
    EXPECT_EQ(1050, result.u.uValue);
}

TEST(VirtualMachine, CallWithTwoArgument)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function calle(x, y)    { return x + y; }";
    str << "function caller()       { return calle(\"foo\", \"bar\"); }";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(2, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> caller = script->_methods[1];

    fuzzer::bytecode::VirtualMachine vm;
    fuzzer::bytecode::Value result;
    
    EXPECT_NO_THROW(result = vm.Execute(*script, *caller));
    EXPECT_EQ(fuzzer::bytecode::Value::STRING, result.type);
    ASSERT_FALSE( !result.stringValue );
    EXPECT_STREQ("foobar", result.stringValue->c_str());
}

///////////////////////////////////////////////////////////////////////////////
//                                  Strings                                  //
///////////////////////////////////////////////////////////////////////////////

///
/// \brief  Tests that two constant strings are appended correctly
///
TEST(VirtualMachine, AppendConstantStrings)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { return \"Hello \" + \"World\";}";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];

    fuzzer::bytecode::VirtualMachine vm;
    fuzzer::bytecode::Value result;
    
    ASSERT_NO_THROW(result = vm.Execute(*script, *method));
    EXPECT_EQ(fuzzer::bytecode::Value::STRING, result.type);
    ASSERT_FALSE( !result.stringValue );
    EXPECT_STREQ("Hello World", result.stringValue->c_str());
}

///
/// \brief  Tests that two constant strings are appended correctly
///
TEST(VirtualMachine, AppendIntegerToString)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { return \"Hello \" + 10;}";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];

    fuzzer::bytecode::VirtualMachine vm;
    fuzzer::bytecode::Value result;
    
    ASSERT_NO_THROW(result = vm.Execute(*script, *method));
    EXPECT_EQ(fuzzer::bytecode::Value::STRING, result.type);
    ASSERT_FALSE( !result.stringValue );
    EXPECT_STREQ("Hello 10", result.stringValue->c_str());
}