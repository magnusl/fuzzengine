#include "fuzzer.h"
#include <limits>
#include <iostream>
#include "ioerror.h"

using namespace std;

namespace fuzzer
{

///
/// \brief  Constructor
///
Fuzzer::Fuzzer() : _ipc(nullptr)
{
    /// register input/output hooks
    _vm.RegisterHandler("out", this);
    _vm.RegisterHandler("out8", this);
    _vm.RegisterHandler("out16", this);
    _vm.RegisterHandler("out32", this);
    _vm.RegisterHandler("in8", this);
    _vm.RegisterHandler("in16", this);
    _vm.RegisterHandler("in32", this);
    _vm.RegisterHandler("trace", this);
    _vm.RegisterHandler("writeln", this);
    _vm.RegisterHandler("readln", this);
}

Fuzzer::~Fuzzer()
{
}

template<class T>
T convert(const bytecode::Value & value)
{
    if (value.type == bytecode::Value::UINT) {
        return static_cast<T>(value.u.uValue);
    } else if (value.type == bytecode::Value::INT) {
        return static_cast<T>(value.u.iValue);
    } else {
        throw std::runtime_error("Unsupported type.");
    }
}

bytecode::Value fromUnsigned(uint64_t value)
{
    bytecode::Value v;
    v.type      = bytecode::Value::UINT;
    v.u.uValue  = value;
    return v;
}

bytecode::Value Fuzzer::Output(const std::string & name, const bytecode::Value & value)
{
    if (name == "out8")         { _ipc->writeU8(convert<uint8_t>(value));   }
    else if (name == "out16")   { _ipc->writeU16(convert<uint16_t>(value)); }
    else if (name == "out32")   { _ipc->writeU32(convert<uint32_t>(value)); }
    else if (name == "out64")   { _ipc->writeU64(convert<uint64_t>(value)); }
    else if (name == "out")     {
        if (value.type == bytecode::Value::OPAQUE) { /// Write vector with binary data
            if (value.opaqueValue && !value.opaqueValue->empty()) {
                if (!_ipc->write(&(*value.opaqueValue)[0], value.opaqueValue->size())) {
                    throw io::IoException("Failed to write opaque value.");
                }
            }
        } else if (value.type == bytecode::Value::STRING) {
            /// Write string
        }
    } else                      { throw std::runtime_error("Unsupported output function."); }

    return bytecode::Value();
}

bytecode::Value Fuzzer::Input(const std::string & name)
{
    if (name == "in8")          { return fromUnsigned(_ipc->readU8());   }
    else if (name == "in16")    { return fromUnsigned(_ipc->readU16()); }
    else if (name == "in32")    { return fromUnsigned(_ipc->readU32()); }
    else if (name == "in64")    { return fromUnsigned(_ipc->readU64()); }
    else                        { throw std::runtime_error("Unsupported input call."); }
}

bytecode::Value Fuzzer::Call(bytecode::VirtualMachine & vm,
    const std::string & func_name,
    const std::vector<bytecode::Value> & arguments)
{
    if (_ipc == nullptr) {
        return bytecode::Value();
    }
    
    /// if the string starts with "out", then we assume that is is a output 
    if (func_name.find("out") == 0) {
        if (arguments.size() != 1) {
            throw std::runtime_error("Unexpected number of arguments for output function.");
        }
        return Output(func_name, arguments[0]);
    } else if (func_name.find("in") == 0) {
        if (!arguments.empty()) {
            throw std::runtime_error("Unexpected arguments for input function.");
        }
        return Input(func_name);
    } else if (func_name == "abort") {
        
    } else if (func_name == "trace") {
        return Trace(func_name, arguments);
    } else if (func_name == "readln") {
        return ReadLine(arguments);
    } else if (func_name == "writeln") {
        return WriteLine(arguments);
    }
    throw std::runtime_error("Unexpected function call.");
}

bytecode::Value Fuzzer::Trace(const std::string & name,
    const std::vector<bytecode::Value> & arguments)
{
    std::cout << "[" << name << "] ";
    for(size_t i = 0; i < arguments.size(); ++i) {
        switch(arguments[i].type) {
        case bytecode::Value::INT:      std::cout << arguments[i].u.iValue; break;
        case bytecode::Value::UINT:     std::cout << arguments[i].u.uValue; break;
        case bytecode::Value::FLOAT:    std::cout << arguments[i].u.fValue; break;
        case bytecode::Value::STRING:   std::cout << (arguments[i].stringValue ? *arguments[i].stringValue : "(null)"); break;
        default:
            break;
        }
    }
    std::cout << std::endl;
    return bytecode::Value();
}

bytecode::Value Fuzzer::WriteLine(const std::vector<bytecode::Value> & arguments)
{
    if (arguments.size() != 1) {
        throw std::runtime_error("writeln() expects a single argument.");
    }
    if (arguments[0].type != bytecode::Value::STRING) {
        throw std::runtime_error("writeln() expects a string argument.");
    }
    const std::string str = *arguments[0].stringValue;

    if (!_ipc->write(str.c_str(), str.size()) || !_ipc->write("\r\n", 2)) {
        throw io::IoException("Failed to write line.");
    }
    return bytecode::Value();
}

bytecode::Value Fuzzer::ReadLine(const std::vector<bytecode::Value> & arguments)
{
    std::string line;
    bool cr = false;
    for(;;) {
        char c = (char) _ipc->readU8();
        if (c == '\r') {
            if (cr) {
                throw io::IoException("Mailformed line, duplicate CR.");
            }
            cr = true;
        } else if (c == '\n') {
            if (cr) { // \r\n
                bytecode::Value v;
                v.type = bytecode::Value::STRING;
                v.stringValue = make_shared<string>(line);
                return v;
            } else {
                throw io::IoException("Mailformed line, expected CR read LF.");
            }
        } else {
            line += c;
            if (line.size() > 8192) {
                throw io::IoException("Mailformed line, line is to long."); 
            }
        }
    }
    throw std::runtime_error("Should never happen.");
}

#if 0
///
/// \brief  Run the fuzzer
///
/// \param [in] Script      The script to run.
/// \param [in] Mutators    The name of the mutators to test.
///
void Fuzzer::Run(const bytecode::Script & Script, const std::list<std::string> & TemplateNames)
{
    // for each template
    for(std::list<std::string>::const_iterator it = TemplateNames.begin();
        it != TemplateNames.end();
        it++)
    {
        map<string,shared_ptr<runtime::Template> >::const_iterator tpIter = Script._templates.find(*it);
        if (tpIter != Script._templates.end()) {
            vector<runtime::Mutator *> mutators = tpIter->second->GetMutators();
            for(size_t i = 0; i < mutators.size(); ++i) {           /// For each assigned mutator
                if (runtime::Mutator * mutator = mutators[i]) {
                    while (!mutator->finished()) {                  /// Mutate until complete
                        _vm.Execute( Script );                      /// Now test this mutation
                        mutator->mutate();                          /// Continue with the next mutation
                    }
                }
            }
        }
    }
}
#endif

} // namespace fuzzer
