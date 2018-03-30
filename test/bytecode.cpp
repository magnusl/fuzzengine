#include <gtest\gtest.h>
#include <fuzzengine\bytecode.h>
#include <fuzzengine\generator.h>
#include <sstream>

using namespace fuzzer::parser;
using namespace fuzzer::bytecode;

TEST(ByteCode, EmptyFunction)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() {}";
    fuzzer::parser::Tokenizer token(str);
    EXPECT_NO_THROW(generator.ParseScript(token));
}

TEST(ByteCode, TemplateByte)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "template x = [ byte ];";
    fuzzer::parser::Tokenizer token(str);
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
}

TEST(ByteCode, TemplateByteWithValue)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "template x = [ byte(255) ];";
    fuzzer::parser::Tokenizer token(str);
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
}

TEST(ByteCode, TemplateWithMultipleValues)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "template x = [ byte(255), word(10), dword(20), qword(30) ];";
    fuzzer::parser::Tokenizer token(str);
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
}

TEST(ByteCode, TemplateMixedTypes)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "template x = [ byte(255), array<dword>(20) ];";
    fuzzer::parser::Tokenizer token(str);
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
}

TEST(ByteCode, ArrayFixedSize)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "template x = [ array<byte>(16) ];";
    fuzzer::parser::Tokenizer token(str);
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
}

TEST(ByteCode, ArrayDynamicSize)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "template x = [{ array<byte>(0-255) }];";
    fuzzer::parser::Tokenizer token(str);
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
}

TEST(ByteCode, PartialFuzzed)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "template x = [ byte(255), { dword(20) } ];";
    fuzzer::parser::Tokenizer token(str);
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
}

TEST(ByteCode, VariableDeclaration)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() {var x = 1;}";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];
    ///
    /// Verify bytecode sequence
    ///
    ASSERT_EQ(2, method->ins.size());
    EXPECT_EQ(push_int(0), method->ins[0]);     // pushint [index 0]
    EXPECT_EQ(set_local(0), method->ins[1]);    // setlocal 0
}

TEST(ByteCode, StringDeclaration)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() {var x = \"Hello World\";}";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];
    ///
    /// Verify bytecode sequence
    ///
    ASSERT_EQ(2, method->ins.size());
    EXPECT_EQ(push_string(0), method->ins[0]);      // pushint [index 0]
    EXPECT_EQ(set_local(0), method->ins[1]);        // setlocal 0
}

TEST(ByteCode, ReturnStatement)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { return 1;}";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];
    ///
    /// Verify bytecode sequence
    ///
    ASSERT_EQ(2, method->ins.size());
    EXPECT_EQ(push_int(0), method->ins[0]);     // pushint [index 0]
    EXPECT_EQ(returnvalue(), method->ins[1]);   // return
}


TEST(ByteCode, MultipleStatements)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() {var x = 1; var y = 2;}";
    fuzzer::parser::Tokenizer token(str);
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];
    ///
    /// Verify bytecode sequence
    ///
    ASSERT_EQ(4, method->ins.size());
    EXPECT_EQ(push_int(0), method->ins[0]);     // pushint [index 0]
    EXPECT_EQ(set_local(0), method->ins[1]);    // setlocal 0
    EXPECT_EQ(push_int(1), method->ins[2]);     // pushint [index 1]
    EXPECT_EQ(set_local(1), method->ins[3]);    // setlocal 1
}

TEST(ByteCode, Add)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() {var x = 1 + 2;}";
    fuzzer::parser::Tokenizer token(str);
    
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];
    ///
    /// Verify bytecode sequence
    ///
    ASSERT_EQ(4, method->ins.size());
    EXPECT_EQ(push_int(0), method->ins[0]);     // pushint [index 0]
    EXPECT_EQ(push_int(1), method->ins[1]);     // pushint [index 1]
    EXPECT_EQ(add(), method->ins[2]);           // add
    EXPECT_EQ(set_local(0), method->ins[3]);    // setlocal 0
}

TEST(ByteCode, Sub)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() {var x = 1 - 2;}";
    fuzzer::parser::Tokenizer token(str);
    
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];
    ///
    /// Verify bytecode sequence
    ///
    ASSERT_EQ(4, method->ins.size());
    EXPECT_EQ(push_int(0), method->ins[0]);     // pushint [index 0]
    EXPECT_EQ(push_int(1), method->ins[1]);     // pushint [index 1]
    EXPECT_EQ(sub(), method->ins[2]);           // sub
    EXPECT_EQ(set_local(0), method->ins[3]);    // setlocal 0
}

TEST(ByteCode, CallNoArguments)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;

    const char * source = 
        "function callee() {}\n"
        "function caller() { callee(); }"; 

    str << source;
    fuzzer::parser::Tokenizer token(str);
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(2, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> caller = script->_methods[1];
    ///
    /// Verify bytecode sequence
    ///
    ASSERT_EQ(2, caller->ins.size());
    EXPECT_EQ(call(0), caller->ins[0]);     // call [index 0]
    EXPECT_EQ(pop(), caller->ins[1]);       // pop
}

TEST(ByteCode, CallSingleArgument)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;

    const char * source = 
        "function callee(x) {}\n"
        "function caller() { callee(1); }"; 

    str << source;
    fuzzer::parser::Tokenizer token(str);
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(2, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> callee = script->_methods[0];
    std::shared_ptr<fuzzer::bytecode::Method> caller = script->_methods[1];

    /// Callee
    ASSERT_EQ(0, callee->ins.size());

    /// Caller
    ASSERT_EQ(3, caller->ins.size());
    EXPECT_EQ(push_int(0), caller->ins[0]); // pushint [index 0]
    EXPECT_EQ(call(0), caller->ins[1]);     // call [index 0]
    EXPECT_EQ(pop(), caller->ins[2]);       // pop
}

TEST(ByteCode, CallExternal)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;

    const char * source = "function caller() { foo(); }"; 

    str << source;
    fuzzer::parser::Tokenizer token(str);
    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> caller = script->_methods[0];

    /// Caller
    ASSERT_EQ(2, caller->ins.size());
    EXPECT_EQ(call_external(0 /**< name index */, 0), caller->ins[0]);  //< call [index 0]
    EXPECT_EQ(pop(), caller->ins[1]);                                                       //< pop
}

TEST(ByteCode, CallExtraArgument)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;

    const char * source = 
        "function callee() {}\n"
        "function caller() { callee(1); }"; 

    str << source;
    fuzzer::parser::Tokenizer token(str);
    EXPECT_THROW(generator.ParseScript(token), std::runtime_error);
}

TEST(ByteCode, MissingArgument)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;

    const char * source = 
        "function callee(a) {}\n"
        "function caller() { callee(); }"; 

    str << source;
    fuzzer::parser::Tokenizer token(str);
    EXPECT_THROW(generator.ParseScript(token), std::runtime_error);
}

TEST(ByteCode, AccessArgument)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;

    str << "function foo(a) { var x = a; }";
    fuzzer::parser::Tokenizer token(str);
    EXPECT_NO_THROW(generator.ParseScript(token));
}
