#ifndef _AST_H_
#define _AST_H_

#include <memory>
#include <list>
#include <stdint.h>

namespace fuzzer {

namespace parser {

enum PrimitiveType {
    UNSIGNED8,
    SIGNED8,
    UNSIGNED16,
    SIGNED16,
    UNSIGNED24,
    SIGNED24,
    UNSIGNED32,
    SIGNED32,
    UNSIGNED64,
    SIGNED64
};

///////////////////////////////////////////////////////////////////////////////
//                                  Expressions                              //
///////////////////////////////////////////////////////////////////////////////

///
/// \class  Expression
///
class Expression {
public:
    ///
    /// \brief  virtual destructor
    ///
    virtual ~Expression() 
    {
    }

    ///
    /// \enum   ExpType
    ///
    enum ExpType {
        EXP_SEQUENCE,
        EXP_FUZZSEQUENCE,
        EXP_CONSTANT,
        EXP_TYPE,
        EXP_REFERENCE,
        EXP_PROP_ACCESS,
        EXP_VECTOR,
    };

    ///
    /// \brief  Returns the expression type
    ///
    virtual ExpType GetType() const = 0;

    ///
    /// Indicates if the expression should be fuzzed or not.
    ///
    bool _fuzzy;
    ///
    /// unique expression identifier
    ///
    size_t _id;
};

///
/// \class  TypeExpression
/// \brief  Only has type information and no value
///
class TypeExpression : public Expression
{
public:
    explicit TypeExpression(PrimitiveType type) : _type(type)
    {
    }

    virtual ExpType GetType() const { return EXP_TYPE; }
    PrimitiveType   _type;
};

///
/// \class  Constant
/// \brief  constant with type and value
///
class Constant : public Expression {
public:
    virtual ExpType GetType() const { return EXP_CONSTANT; }

    union {
        uint64_t    u64;
        int64_t     i64;
        uint32_t    u32;
        int32_t     i32;
        uint16_t    u16;
        int16_t     i16;
        uint8_t     u8;
        int8_t      i8;
        float       f;
        double      d;
    } u;

    bool            _hasValue;
    PrimitiveType   _type;
};

///
/// \class  Reference
/// \brief  Reference to variable
///
class Reference : public Expression {
public:
    virtual ExpType GetType() const { return EXP_REFERENCE; }
    std::string _name;
};

///
/// \class  PropertyAccess
/// \brief  Access to variable property
///
class PropertyAccess : public Expression {
public:
    virtual ExpType GetType() const { return EXP_PROP_ACCESS; }
    std::string _name;
    std::string _propname;
};

///
/// \class  Vector
/// \brief  Represents an array or vector
///
class Vector : public Expression {
public:
    virtual ExpType GetType() const { return EXP_VECTOR; }

    PrimitiveType   _type;
    size_t          _lower, _upper;
};

///
/// \class Sequence
///
class Sequence : public Expression {
public:
    virtual ExpType GetType() const { return EXP_SEQUENCE; }
    std::list<std::shared_ptr<Expression> >     _expressions;
};

///
/// \class  FuzzSequence
///
class FuzzSequence : public Sequence {
public:
    virtual ExpType GetType() const { return EXP_FUZZSEQUENCE; }
    std::list<std::shared_ptr<Expression> >     _expressions;
};

///////////////////////////////////////////////////////////////////////////////
//                                  Statements                               //
///////////////////////////////////////////////////////////////////////////////

///
/// \class  Statement
///
class Statement {
public:
    ///
    /// \enum   Type
    /// \brief  The different statement types
    ///
    enum Type {
        STMT_DECL,      // declaration
        STMT_OUT,       // output statement
        STMT_IN         // input statement
    };

    ///
    /// \brief  Returns the statement type
    ///
    virtual Type GetType() const = 0;
};

///
/// \class  Declaration
/// \brief  Variable declaration, e.g. "$variable = [....];"
///
class Declaration : public Statement {
public:
    virtual Type GetType() const { return STMT_DECL; }

    std::shared_ptr<Expression>     _value;
    std::string                     _name;
};

///
/// \class  Output
/// \brief  Output one or more statements
///
class Output : public Statement {
public:
    virtual Type GetType() const { return STMT_OUT; }

    std::list<std::shared_ptr<Expression> > _expressions;
};

///
/// \class  Input
///
class Input : public Statement {
public:

    virtual Type GetType() const { return STMT_IN; }

    std::shared_ptr<Sequence>   _input;
    std::string                 _name;
};

} // namespace parser

} // namespace fuzzer

#endif