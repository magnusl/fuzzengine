#include <gtest\gtest.h>
#include <fuzzengine\bytecode.h>
#include <fuzzengine\generator.h>
#include <fuzzengine\vm.h>
#include <sstream>

using namespace fuzzer::parser;
using namespace fuzzer::bytecode;

class FunctionHandler : public IRuntimeHandler
{
public:
    FunctionHandler() : _called(false)
    {
    }

    Value Call(VirtualMachine & vm, const std::string & name,
        const std::vector<Value> & arguments)
    {
        _called = true;
        Value v;
        v.type = Value::UNDEFINED;
        return v;
    }

    bool called() const { return _called; }

protected:
    bool _called;
};

///
/// Calls a method that wasn't defined in the script, but is defined in the 
/// VM runtime.
///
TEST(External, CallExternal)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { putu8(10); }";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];

    fuzzer::bytecode::VirtualMachine vm;
    fuzzer::bytecode::Value result;
    
    FunctionHandler handler;
    vm.RegisterHandler("putu8", &handler);

    ASSERT_NO_THROW(result = vm.Execute(*script, *method));
    EXPECT_TRUE(handler.called());
    EXPECT_EQ(Value::UNDEFINED, result.type);
}

///
/// Calls a method that wasn't defined in the script, and isn't part of the 
/// VM runtime.
///
TEST(External, CallUnknown)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { putu8(10); }";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];

    fuzzer::bytecode::VirtualMachine vm;
    fuzzer::bytecode::Value result;
    
    EXPECT_THROW(result = vm.Execute(*script, *method), std::runtime_error);
}

TEST(External, CallTrace)
{
    fuzzer::bytecode::Generator generator;
    std::stringstream str;
    str << "function x() { trace(\"Hello\", 10); }";
    fuzzer::parser::Tokenizer token(str);

    std::shared_ptr<fuzzer::bytecode::Script> script;
    ASSERT_NO_THROW(script = generator.ParseScript(token));
    ASSERT_EQ(1, script->_methods.size());

    std::shared_ptr<fuzzer::bytecode::Method> method = script->_methods[0];

    ASSERT_EQ(4,  method->ins.size());
    EXPECT_EQ(push_string(0), method->ins[0]);
    EXPECT_EQ(push_int(0), method->ins[1]);             // pushint [10]
    EXPECT_EQ(call_external(1, 2), method->ins[2]);
    EXPECT_EQ(pop(), method->ins[3]);                   // pop
}