#ifndef _FUZZER_H_
#define _FUZZER_H_

#include "vm.h"
#include "script.h"
#include "io.h"

#include <list>
#include <string>

namespace fuzzer
{

///
/// \class  Fuzzer
///
class Fuzzer : public bytecode::IRuntimeHandler
{
public:
    Fuzzer();
    virtual ~Fuzzer();

protected:

    virtual bytecode::Value Call(bytecode::VirtualMachine &, const std::string &,
        const std::vector<bytecode::Value> &);
    bytecode::Value Output(const std::string &, const bytecode::Value &);
    bytecode::Value Input(const std::string &);
    bytecode::Value Trace(const std::string &, const std::vector<bytecode::Value> & arguments);
    bytecode::Value WriteLine(const std::vector<bytecode::Value> & arguments);
    bytecode::Value ReadLine(const std::vector<bytecode::Value> & arguments);

protected:

    bytecode::VirtualMachine _vm;
    io::Ipc * _ipc;
};

} // namespace fuzzer

#endif
