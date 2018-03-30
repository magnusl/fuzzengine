#ifndef _TOKEN_H_
#define _TOKEN_H_

#include <iostream>
#include "pool.h"
#include <vector>

namespace fuzzer {

namespace parser {

typedef enum {
    T_IDENT,

    T_KEYWORD_BYTE,
    T_KEYWORD_WORD,
    T_KEYWORD_DWORD,
    T_KEYWORD_QWORD,
    T_KEYWORD_ARRAY,
    T_KEYWORD_CSTRING,
    T_KEYWORD_PASCAL_STRING,
    T_KEYWORD_LINE,

    /** keywords */
    T_KEYWORD_U8,
    T_KEYWORD_U16,
    T_KEYWORD_U24,
    T_KEYWORD_U32,
    T_KEYWORD_U64,
    T_KEYWORD_S8,
    T_KEYWORD_S16,
    T_KEYWORD_S24,
    T_KEYWORD_S32,
    T_KEYWORD_S64,

    T_DOLLARSIGN,       // "$variable"
    T_OUTPUT,       // "<<"
    T_INPUT,
    T_TEMPLATE,
    T_FUNCTION,
    T_VAR,

    T_RETURN,
    T_STRING,

    T_KEYWORD_IN,
    T_KEYWORD_OUT,
    T_KEYWORD_NODE,
    T_KEYWORD_QUERY,
    T_KEYWORD_EVENT,
    T_KEYWORD_TRUE,
    T_KEYWORD_FALSE,
    /** types */
    T_TYPE_FLOAT,
    T_TYPE_BOOL,
    T_INTEGER,
    T_REAL,
    T_ASSIGN,
    /** single character tokens */
    T_QUESTION,
    T_COMMA,
    T_SEMICOLON,
    T_COLON,
    T_DOT,
    T_LEFT_PAREN,               /* ( */
    T_RIGHT_PAREN,              /* ) */
    T_LEFT_SQUARE_BRACKET,      /* [ */
    T_RIGHT_SQUARE_BRACKET,     /* ] */
    T_LEFT_CURLY_BRACKET,       /* { */
    T_RIGHT_CURLY_BRACKET,       /* } */
    /** operators */
    T_ADD,
    T_SUB,
    T_MUL,
    T_DIV,
    T_EQUAL,
    T_LESS,
    T_GRT,
    T_LEQ,
    T_GEQ,
    /** Parse error */
    T_FAILURE,
    /** eof */
    T_EOF
} Symbol_t;

class SymbolTable
{
public:
    SymbolTable()
    {
    }

    typedef size_t SymIndex;

    SymIndex Insert(const char *, bool modify = true);
    const char * Retrive(SymIndex index)    const;

protected:
    std::vector<std::string>    _strings;
};

struct PositionInfo
{
    PositionInfo() : Row(0), Col(0)
    {
    }

    size_t      Row;
    size_t      Col;
};

class Tokenizer
{
public:
    explicit Tokenizer(std::istream & is) : m_Stream(is), m_State(TOK_INITIAL), m_HasPeeked(false)
    {
    }

    Symbol_t    GetSym();
    Symbol_t    Peek();

    SymbolTable::SymIndex       SymIndex() const            { return u.m_SymbolIndex; }
    float                       RealValue() const           { return u.m_RealValue; }
    int                         IntValue() const            { return u.m_IntValue; }
    SymbolTable &               SymbolTable()               { return m_SymbolTable; }
    const PositionInfo &        Position() const            { return m_Position; }

    const char *                Lookup(SymbolTable::SymIndex sym) const
    {
        return m_SymbolTable.Retrive(sym);
    }

    static const char *         GetTokenString(Symbol_t);

protected:
    Tokenizer(const Tokenizer &);
    Tokenizer & operator=(const Tokenizer &);

    enum {
        TOK_INITIAL,
        TOK_NUMERIC,
        TOK_IDENT,
        TOK_FLOAT,
        TOK_STRING,
    } m_State;

    bool Peek(char &);
    bool GetChar(char &);

    Symbol_t        m_NextSym;
    bool            m_HasPeeked;

    std::istream &                  m_Stream;
    parser::SymbolTable             m_SymbolTable;
    PositionInfo                    m_Position;

    union {
        SymbolTable::SymIndex           m_SymbolIndex;
        float                           m_RealValue;
        int                             m_IntValue;
    } u;
};

} // namespace parser

} // namespace flow

#endif