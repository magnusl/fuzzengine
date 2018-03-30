#ifndef _VM_H_
#define _VM_H_

#include "script.h"
#include <map>

namespace fuzzer {

namespace bytecode {

class VirtualMachine;

///
/// \brief  handler for runtime functions
///
class IRuntimeHandler
{
public:
    virtual bytecode::Value Call(VirtualMachine &, const std::string &,
        const std::vector<bytecode::Value> &) = 0;
};

///
/// \class  VirtualMachine
///
class VirtualMachine
{
public:
    ///
    /// \brief  Executes a script
    ///
    void Execute(const Script &);

    ///
    /// \brief  Executes a bytecode method
    ///
    bytecode::Value Execute(const Script &, const bytecode::Method &);
    bytecode::Value Execute(const Script &, const bytecode::Method &,
        const std::vector<bytecode::Value> &);

    void RegisterHandler(const std::string &, IRuntimeHandler *);

protected:
    std::map<std::string, IRuntimeHandler *> _handlers;
};

} // namespace runtime

} // namespace fuzzer

#endif