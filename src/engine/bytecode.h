#ifndef _BYTECODE_H_
#define _BYTECODE_H_

#include <stdint.h>
#include <vector>
#include <string>
#include <map>
#include "parser.h"
#include <memory>

namespace fuzzer {

namespace bytecode {

///
/// \enum   Opcode
/// \brief  Defines the supported opcodes
///
enum Opcode {
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_CALL,
    OP_CALLVOID,
    OP_CALLEXT,
    OP_SIZEOF,
    OP_PUSHINT,
    OP_PUSHSTRING,
    OP_SETLOCAL,
    OP_GETLOCAL,
    OP_GETARG,
    OP_GETTEMPLATE,
    OP_LOOKUP,
    OP_POP,         //< pop item from stack
    OP_RETURN,      //< return the top of the stack
};

///
/// \class  Instruction
/// \brief  Bytecode instruction
///
struct Instruction {
    uint32_t    opcode  : 8;
    union {
        uint32_t    idx     : 16;
        uint32_t    name    : 16;
    };
    uint32_t    count : 8;
    bool operator ==(const Instruction & ins) const {
        return (opcode == ins.opcode) && (idx == ins.idx) && (count == ins.count);
    }   
};

inline Instruction pop() {
    Instruction i; i.opcode = OP_POP; i.idx = 0;
    return i;
}

inline Instruction set_local(uint16_t idx) { 
    Instruction i; i.opcode = OP_SETLOCAL; i.idx = idx;
    return i;
}

inline Instruction get_local(uint16_t idx) { 
    Instruction i; i.opcode = OP_GETLOCAL; i.idx = idx;
    return i;
}

inline Instruction get_argument(uint16_t idx) { 
    Instruction i; i.opcode = OP_GETARG; i.idx = idx;
    return i;
}

inline Instruction add() {
    Instruction i; i.opcode = OP_ADD;
    return i;
}

inline Instruction sub() {
    Instruction i; i.opcode = OP_SUB;
    return i;
}

inline Instruction div() {
    Instruction i; i.opcode = OP_MUL;
    return i;
}

inline Instruction mul() {
    Instruction i; i.opcode = OP_DIV;
    return i;
}

inline Instruction push_int(uint16_t idx) {
    Instruction i; i.opcode = OP_PUSHINT; i.idx = idx;
    return i;
}

inline Instruction push_string(uint16_t idx) {
    Instruction i; i.opcode = OP_PUSHSTRING; i.idx = idx;
    return i;
}

inline Instruction call(uint16_t idx) { 
    Instruction i; i.opcode = OP_CALL; i.idx = idx;
    return i;
}

inline Instruction call_external(uint16_t name, uint16_t argument_count) {
    Instruction i;
    i.opcode = OP_CALLEXT;
    i.name = name;
    i.count = argument_count;
    return i;
}

inline Instruction get_template(uint16_t name) { 
    Instruction i; i.opcode = OP_GETTEMPLATE; i.name = name;
    return i;
}

inline Instruction returnvalue() {
    Instruction i; i.opcode = OP_RETURN;
    return i;
}

///
/// \class  Method
/// \brief  Bytecode method
///
struct Method {
    std::vector<size_t>         arguments;
    // The instructions to execute
    std::vector<Instruction>    ins;
    // locals
    std::map<size_t, size_t>    locals;
    // Constants
    std::vector<int>            constant_ints;
    std::vector<std::string>    constant_strings;
    std::string                 name;
    size_t                      name_index;
    size_t                      num_locals;
    size_t                      method_index;
};

///
/// \class  Bytecode value
///
struct Value {
    
    Value() : type(UNDEFINED)
    {
    }

    enum ValueType {
        UNDEFINED,
        INT,
        UINT,
        FLOAT,
        STRING,
        OPAQUE,
    } type;

    union {
        int64_t     iValue;
        uint64_t    uValue;
        float       fValue;
    } u;

    std::shared_ptr<std::string>            stringValue;
    std::shared_ptr<std::vector<uint8_t> >  opaqueValue;
};

} // namespace bytecode

} // namespace fuzzer

#endif