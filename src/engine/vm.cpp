#include "vm.h"
#include <vector>
#include <sstream>
#include <assert.h>

using namespace std;

namespace fuzzer {

namespace bytecode {

bytecode::Value pop(vector<bytecode::Value> & operandStack)
{
    if (operandStack.empty()) {
        throw std::runtime_error("Cannot pop value from empty stack.");
    }
    Value v = operandStack.back();
    operandStack.pop_back();
    return v;
}

void push(vector<bytecode::Value> & operandStack, const bytecode::Value & value)
{
    operandStack.push_back( value );
}

void push(vector<bytecode::Value> & operandStack, int value)
{
    Value v;
    v.type = Value::INT;
    v.u.iValue = value;
    operandStack.push_back(v);
}

void push(vector<bytecode::Value> & operandStack, const std::string & value)
{
    Value v;
    v.type = Value::STRING;
    v.stringValue = make_shared<string>(value);
    operandStack.push_back(v);
}

///////////////////////////////////////////////////////////////////////////////
//                              Bytecode instructions                        //
///////////////////////////////////////////////////////////////////////////////

///
/// \brief  Append a value to a string
///
bytecode::Value append_string(const Value & lhs, const Value & rhs)
{
    if ((lhs.type != Value::STRING) || (!lhs.stringValue)) {
        throw std::runtime_error("Left hand size expression is not a valid string.");
    }

    stringstream ss;
    ss << *lhs.stringValue;

    switch(rhs.type) {
    case Value::INT:        ss << rhs.u.iValue; break;
    case Value::UINT:       ss << rhs.u.uValue; break;
    case Value::FLOAT:      ss << rhs.u.fValue; break;
    case Value::STRING:     ss << *rhs.stringValue; break;
    default:
        throw std::runtime_error("TypeError: cannot append to string.");
    }
    Value v;
    v.type          = Value::STRING;
    v.stringValue   = std::make_shared<std::string>();
    v.stringValue->assign(ss.str());
    return v;
}

///
/// \brief  Addition between two values
///
bytecode::Value add(const Value & lhs, const Value & rhs)
{
    Value v;
    switch(lhs.type)
    {
    case Value::INT:
        v.type = Value::INT;
        switch(rhs.type) {
        case Value::INT:    v.u.iValue = lhs.u.iValue + rhs.u.iValue; break;
        case Value::UINT:   v.u.uValue = lhs.u.iValue + rhs.u.uValue; break;
        case Value::FLOAT:  v.type = Value::FLOAT; v.u.fValue = lhs.u.iValue + rhs.u.fValue; break;
        default:            throw std::runtime_error("TypeError.");
        }
        break;
    case Value::UINT:
        v.type = Value::UINT;
        switch(rhs.type) {
        case Value::INT:    v.type = Value::INT; v.u.iValue = lhs.u.uValue + rhs.u.iValue; break;
        case Value::UINT:   v.u.iValue = lhs.u.uValue + rhs.u.uValue; break;
        case Value::FLOAT:  v.type = Value::FLOAT; v.u.fValue = lhs.u.uValue + rhs.u.fValue; break;
        default:            throw std::runtime_error("TypeError.");
        }
        break;
    case Value::STRING:
        v.type = Value::STRING;
        switch(rhs.type) {
        case Value::INT:
        case Value::UINT:
        case Value::FLOAT:
        case Value::STRING:
            return append_string(lhs, rhs);
        default:
            throw std::runtime_error("TypeError.");
        }
        break;
    case Value::OPAQUE:
        if (rhs.type != Value::OPAQUE) {
            throw std::runtime_error("TypeError.");
        }
        v.type = Value::OPAQUE;
        v.opaqueValue = make_shared<vector<uint8_t> >();
        v.opaqueValue->insert(v.opaqueValue->end(), lhs.opaqueValue->begin(), lhs.opaqueValue->end());
        v.opaqueValue->insert(v.opaqueValue->end(), rhs.opaqueValue->begin(), rhs.opaqueValue->end());
        break;
    }
    return v;
}

bytecode::Value sub(const Value & lhs, const Value & rhs)
{
    Value v;
    switch(lhs.type) {
    case Value::INT:
        switch(rhs.type) {
        case Value::INT:    v.type = Value::INT; v.u.iValue = lhs.u.iValue - rhs.u.iValue; break;
        case Value::UINT:   v.type = Value::INT; v.u.iValue = lhs.u.iValue - rhs.u.uValue; break;
        case Value::FLOAT:  v.type = Value::FLOAT; v.u.fValue = lhs.u.iValue - rhs.u.fValue; break;
        default:            throw std::runtime_error("TypeError.");
        }
    case Value::UINT:
        switch(rhs.type) {
        case Value::INT:    v.type = Value::INT; v.u.iValue = lhs.u.uValue - rhs.u.iValue; break;
        case Value::UINT:   v.type = Value::UINT; v.u.uValue = lhs.u.uValue - rhs.u.uValue; break;
        case Value::FLOAT:  v.type = Value::FLOAT; v.u.fValue = lhs.u.uValue - rhs.u.fValue; break;
        default:            throw std::runtime_error("TypeError.");
        }
    case Value::FLOAT:
        switch(rhs.type) {
        case Value::INT:    v.type = Value::FLOAT; v.u.fValue = lhs.u.fValue - rhs.u.iValue; break;
        case Value::UINT:   v.type = Value::FLOAT; v.u.fValue = lhs.u.fValue - rhs.u.uValue; break;
        case Value::FLOAT:  v.type = Value::FLOAT; v.u.fValue = lhs.u.fValue - rhs.u.fValue; break;
        default:            throw std::runtime_error("TypeError.");
        }
    default:
        throw std::runtime_error("TypeError.");
    }
    return v;
}

bytecode::Value mul(const Value & lhs, const Value & rhs)
{
    Value v;
    switch(lhs.type) {
    case Value::INT:
        switch(rhs.type) {
        case Value::INT:    v.type = Value::INT; v.u.iValue = lhs.u.iValue * rhs.u.iValue; break;
        case Value::UINT:   v.type = Value::INT; v.u.iValue = lhs.u.iValue * rhs.u.uValue; break;
        case Value::FLOAT:  v.type = Value::FLOAT; v.u.fValue = lhs.u.iValue * rhs.u.fValue; break;
        default:            throw std::runtime_error("TypeError.");
        }
    case Value::UINT:
        switch(rhs.type) {
        case Value::INT:    v.type = Value::INT; v.u.iValue = lhs.u.uValue * rhs.u.iValue; break;
        case Value::UINT:   v.type = Value::UINT; v.u.uValue = lhs.u.uValue * rhs.u.uValue; break;
        case Value::FLOAT:  v.type = Value::FLOAT; v.u.fValue = lhs.u.uValue * rhs.u.fValue; break;
        default:            throw std::runtime_error("TypeError.");
        }
    case Value::FLOAT:
        switch(rhs.type) {
        case Value::INT:    v.type = Value::FLOAT; v.u.fValue = lhs.u.fValue * rhs.u.iValue; break;
        case Value::UINT:   v.type = Value::FLOAT; v.u.fValue = lhs.u.fValue * rhs.u.uValue; break;
        case Value::FLOAT:  v.type = Value::FLOAT; v.u.fValue = lhs.u.fValue * rhs.u.fValue; break;
        default:            throw std::runtime_error("TypeError.");
        }
    default:
        throw std::runtime_error("TypeError.");
    }
    return v;
}

void throw_on_zero(const Value & value)
{
    switch(value.type) {
    case Value::INT:    if (value.u.iValue == 0) throw std::runtime_error("Integer is zero."); break;
    case Value::UINT:   if (value.u.uValue == 0) throw std::runtime_error("Unsigned Integer is zero."); break;
    case Value::FLOAT:  if (value.u.fValue == 0) throw std::runtime_error("Float is zero."); break;
    default:            break;
    }
}

bytecode::Value div(const Value & lhs, const Value & rhs)
{
    /// prevent division by zero
    throw_on_zero(rhs);
    Value v;
    switch(lhs.type) {
    case Value::INT:
        switch(rhs.type) {
        case Value::INT:    v.type = Value::INT; v.u.iValue = lhs.u.iValue / rhs.u.iValue; break;
        case Value::UINT:   v.type = Value::INT; v.u.iValue = lhs.u.iValue / rhs.u.uValue; break;
        case Value::FLOAT:  v.type = Value::FLOAT; v.u.fValue = lhs.u.iValue / rhs.u.fValue; break;
        default:            throw std::runtime_error("TypeError.");
        }
    case Value::UINT:
        switch(rhs.type) {
        case Value::INT:    v.type = Value::INT; v.u.iValue = lhs.u.uValue / rhs.u.iValue; break;
        case Value::UINT:   v.type = Value::UINT; v.u.uValue = lhs.u.uValue / rhs.u.uValue; break;
        case Value::FLOAT:  v.type = Value::FLOAT; v.u.fValue = lhs.u.uValue / rhs.u.fValue; break;
        default:            throw std::runtime_error("TypeError.");
        }
    case Value::FLOAT:
        switch(rhs.type) {
        case Value::INT:    v.type = Value::FLOAT; v.u.fValue = lhs.u.fValue / rhs.u.iValue; break;
        case Value::UINT:   v.type = Value::FLOAT; v.u.fValue = lhs.u.fValue / rhs.u.uValue; break;
        case Value::FLOAT:  v.type = Value::FLOAT; v.u.fValue = lhs.u.fValue / rhs.u.fValue; break;
        default:            throw std::runtime_error("TypeError.");
        }
    default:
        throw std::runtime_error("TypeError.");
    }
    return v;
}

bytecode::Value SizeOf(const Value & lhs)
{
    Value v;
    switch(lhs.type) {
    case Value::OPAQUE: v.u.uValue = lhs.opaqueValue ? lhs.opaqueValue->size() : 0; break;
    case Value::STRING: v.u.uValue = lhs.stringValue ? lhs.stringValue->size() : 0; break;
    default:
        throw std::runtime_error("TypeError: sizeof operator cannot be applied to primitive type.");
    }
    return v;
}

void VirtualMachine::RegisterHandler(const std::string & name,
    IRuntimeHandler * handler)
{
    _handlers[name] = handler;
}

void VirtualMachine::Execute(const Script & script)
{
    std::shared_ptr<bytecode::Method> method = script.findMethod("main");
    if (method) {
        Execute(script, *method);
    } else {
        throw std::runtime_error("Script cannot be executed since it is missing the 'main' method.");
    }
}

bytecode::Value VirtualMachine::Execute(const Script & script,
    const bytecode::Method & method)
{
    vector<bytecode::Value> arguments;
    return Execute(script, method, arguments);
}

bytecode::Value VirtualMachine::Execute(const Script & script,
    const bytecode::Method & method,
    const std::vector<bytecode::Value> & arguments)
{
    vector<bytecode::Value> locals(method.num_locals);
    vector<bytecode::Value> operandStack;

    for(size_t i = 0, count = method.ins.size(); i < count; ++i) {
        const Instruction & ins = method.ins[i];
        switch( ins.opcode ) {
            case OP_ADD:
            {
                Value rhs = pop(operandStack);
                Value lhs = pop(operandStack);
                push( operandStack, add( lhs, rhs ));
                break;
            }
            case OP_SUB:
            {
                Value rhs = pop(operandStack);
                Value lhs = pop(operandStack);
                push( operandStack, sub( lhs, rhs ));
                break;
            }
            case OP_MUL:
            {
                Value rhs = pop(operandStack);
                Value lhs = pop(operandStack);
                push( operandStack, mul( lhs, rhs ));
                break;
            }
            case OP_DIV:
            {
                Value rhs = pop(operandStack);
                Value lhs = pop(operandStack);
                push( operandStack, div( lhs, rhs ));
                break;
            }
            case OP_SIZEOF:     push(operandStack, SizeOf(pop(operandStack))); break;
            case OP_SETLOCAL:   locals[ins.idx] = pop(operandStack); break;
            case OP_GETLOCAL:   push(operandStack, locals[ins.idx]); break;
            case OP_GETARG:
                if (ins.idx < arguments.size()) {
                    push(operandStack, arguments[ins.idx]);
                } else {
                    throw std::runtime_error("Invalid argument index.");
                }
                break;
            case OP_POP:        pop(operandStack); break;
            case OP_PUSHINT:    push(operandStack, method.constant_ints[ins.idx]); break;
            case OP_PUSHSTRING: push(operandStack, method.constant_strings[ins.idx]); break;
            case OP_CALL:
            {
                /// Perform method call
                vector<Value> arguments;
                if (ins.idx < script._methods.size()) {
                    shared_ptr<bytecode::Method> callee = script._methods[ins.idx];
                    /// pop the arguments of the stack
                    if (!callee->arguments.empty()) {
                        size_t count = callee->arguments.size();
                        arguments.resize(count);
                        for(size_t i = 0; i < count; ++i) {
                            arguments[count - i - 1] = pop(operandStack);
                        }
                    }
                    /// call the method and push it return value onto the operand stack
                    push(operandStack, Execute(script, *callee, arguments));
                }
                break;
            }
            case OP_CALLEXT:    // call a runtime function
            {
                const std::string funcName = method.constant_strings[ins.name];
                map<string, IRuntimeHandler *>::iterator it = _handlers.find(funcName);
                if (it == _handlers.end()) {
                    throw runtime_error("Unknown runtime method.");
                }
                vector<Value> arguments(ins.count);
                for(size_t i = 0; i < ins.count; ++i) {
                    arguments[ins.count - i - 1] = pop(operandStack);
                }
                if (it->second) {
                    push(operandStack, it->second->Call(*this, funcName, arguments));
                } else {
                    throw std::runtime_error("Invalid IRuntimeHandler.");
                }
                break;
            }
            case OP_GETTEMPLATE:
            {
                if (ins.name < method.constant_strings.size()) {
                    const std::string & name = method.constant_strings[ins.name];
                    map<string, shared_ptr<runtime::Template> >::const_iterator tp = script._templates.find(name);
                    if (tp == script._templates.end()) {
                        throw std::runtime_error("Unknown template.");
                    }
                    /// generate template, and push it on the stack
                    Value v;
                    v.opaqueValue   = make_shared<vector<uint8_t> >();
                    v.type          = Value::OPAQUE;
                    tp->second->generate(*v.opaqueValue);
                    push(operandStack, v);
                } else {
                    throw std::runtime_error("Invalid string index.");
                }
                break;
            }
            case OP_RETURN: return pop(operandStack);
            default:
                throw std::runtime_error("Unknown instruction.");
        }
    }
    /// if we reached the end of the function without a return so push UNDEFINED
    Value ret;
    ret.type = Value::UNDEFINED;
    return ret;
}

} // namespace bytecode

} // namespace fuzzer