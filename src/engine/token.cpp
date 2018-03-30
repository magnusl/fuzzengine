#include "token.h"
#include <sstream>
#include <string>
#include <cctype>

using namespace std;

#define stringify( name ) #name

namespace fuzzer {

namespace parser  {

using std::string;

/** Single characters tokens */
static struct {
    char        c;
    Symbol_t    sym;
} SingleTokens[] = {
    { ';', T_SEMICOLON },
    { ':', T_COLON },
    { '.', T_DOT },
    { '?', T_QUESTION },
    { ',', T_COMMA },
    { '(', T_LEFT_PAREN },
    { ')', T_RIGHT_PAREN },
    { '{', T_LEFT_CURLY_BRACKET },
    { '}', T_RIGHT_CURLY_BRACKET },
    { '[', T_LEFT_SQUARE_BRACKET },
    { ']', T_RIGHT_SQUARE_BRACKET },
    { '+', T_ADD },
    { '-', T_SUB },
    { '*', T_MUL },
    { '/', T_DIV },
    { '$', T_DOLLARSIGN}
};

/** Keywords */
static struct {
    const char *    keyword;
    Symbol_t        sym;
} Keywords[] = {
    { "u8", T_KEYWORD_U8},
    { "u16", T_KEYWORD_U16},
    { "u24", T_KEYWORD_U24},
    { "u32", T_KEYWORD_U32},
    { "u64", T_KEYWORD_U64},
    { "byte", T_KEYWORD_BYTE},
    { "word", T_KEYWORD_WORD},
    { "dword", T_KEYWORD_DWORD},
    { "qword", T_KEYWORD_QWORD},
    { "array", T_KEYWORD_ARRAY},
    { "function", T_FUNCTION},
    { "template", T_TEMPLATE},
    { "return", T_RETURN },
    { "var", T_VAR },
    { "cstring", T_KEYWORD_CSTRING },
    { "pascalstring", T_KEYWORD_PASCAL_STRING },
    { "line", T_KEYWORD_LINE }
};

bool Tokenizer::GetChar(char & c)
{
    if (!m_Stream.get(c)) {
        return false;
    }

    /** Update the position */
    switch (c) {
    case '\n':      ++m_Position.Row; m_Position.Col = 0; break;
    case '\t':      m_Position.Col += 4; break;
    default:        ++m_Position.Col; break;
    }

    return true;
}

bool Tokenizer::Peek(char & c)
{
    c = m_Stream.peek();
    if (c == EOF) {
        return false;
    }
    return true;
}

/**
 * Peek at the next symbol without consuming it.
 */
Symbol_t Tokenizer::Peek()
{
    if (!m_HasPeeked) {
        m_NextSym = GetSym();
        m_HasPeeked = true;
    }
    return m_NextSym;
}

Symbol_t Tokenizer::GetSym()
{
    m_State = TOK_INITIAL;
    if (m_HasPeeked) {
        m_HasPeeked = false;
        return m_NextSym;
    }
    char c;
    string value;
    if (!GetChar(c)) {
        return T_EOF;   /** end-of-file */
    }
    for (;;) {
        switch (m_State)
        {
        case TOK_INITIAL:    /** handle single character tokens */
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                if (!GetChar(c)) {
                    return T_EOF;
                }
                continue;
            }
            if (c == '"') {
                m_State = TOK_STRING;
                value   = "";
                continue;
            }
            for (size_t i = 0; i < sizeof(SingleTokens) / sizeof(SingleTokens[0]); i++) {
                if (SingleTokens[i].c == c) {
                    return SingleTokens[i].sym;
                }
            }
            if (c == '=') {
                /** either assign or equal */
                return (Peek(c) ? ((c == '=') ? (GetChar(c), T_EQUAL) : T_ASSIGN) : T_ASSIGN);
            }
            else if (c == '<') {
                /** either T_LESS or T_LEQ */
                if (Peek(c)) {
                    if (c == '=')       return (GetChar(c), T_LEQ);
                    else if (c == '<')  return (GetChar(c), T_OUTPUT);
                    else                return T_LESS;
                } else {
                    return T_LESS;
                }
            }
            else if (c == '>') {
                /** either T_GRT, T_GRT pr T_INPUT */
                if (Peek(c)) {
                    if (c == '=')       return (GetChar(c), T_GEQ);
                    else if (c == '>')  return (GetChar(c), T_INPUT);
                    else                return T_GRT;
                } else {
                    return T_GRT;
                }
            }
            else if (isdigit(c)) {
                m_State = TOK_NUMERIC;
                value += c;
                continue;
            }
            else if (std::isalpha(c)) {
                m_State = TOK_IDENT;
                value += c;
                continue;
            }
            else {
                /** error */
            }
        case TOK_IDENT:
            while (Peek(c) && (std::isalnum(c) || (c == '_')))
            {
                GetChar(c);
                value += c;
            }
            /** match it against known keywords */
            for (size_t i = 0; i < sizeof(Keywords) / sizeof(Keywords[0]); i++) {
                if (value == Keywords[i].keyword) {
                    return Keywords[i].sym;
                }
            }
            u.m_SymbolIndex = m_SymbolTable.Insert(value.c_str());
            return T_IDENT;
        case TOK_NUMERIC:   /** integer or floating point numbr */
            while (Peek(c)) {
                if (std::isdigit(c)) {
                    GetChar(c);
                    value += c;
                }
                else if (c == '.') {
                    GetChar(c);
                    m_State = TOK_FLOAT;
                    value += c;
                    break;
                } else {
                    break;  /** return T_INTEGER */
                }
            }
            if (m_State == TOK_NUMERIC) {
                std::stringstream ss;
                ss << value;
                if (!(ss >> u.m_IntValue)) {
                    return T_FAILURE;
                }
                return T_INTEGER;
            }
            break;
        case TOK_FLOAT:
            while (Peek(c)) {
                if (std::isdigit(c)) {
                    GetChar(c);
                    value += c;
                }
                else if (c == 'f') {
                    GetChar(c);
                    break;
                }
                else {
                    break;
                }
            }
            /** convert to float */
            {
                std::stringstream ss;
                ss << value;
                if (!(ss >> u.m_RealValue)) {
                    return T_FAILURE;
                }
                return T_REAL;
            }
            break;
        case TOK_STRING:
            while (GetChar(c)) {
                if (c == '"') {
                    u.m_SymbolIndex = m_SymbolTable.Insert(value.c_str());
                    return T_STRING;
                } else if (c == '\n' || c == '\r' || (c == 0)) {
                    return T_FAILURE;
                } else if (c == '\\') {
                    if (!GetChar(c)) {
                        return T_FAILURE;
                    }
                    switch(c) {
                    case '\\':  c += '\\'; break; // '\'
                    case 'n':   c += '\n'; break; // newline
                    case 'r':   c += '\r'; break; // carriage return
                    case 't':   c += '\t'; break; // tab
                    }
                } else {
                    value += c;
                }
            }
            return T_FAILURE;
            break;
        }
    }
}

/**
 * Returns the string associated with the SymIndex, or null.
 */
const char * SymbolTable::Retrive(SymbolTable::SymIndex index) const
{
    if (index < this->_strings.size()) {
        return _strings[index].c_str();
    }
    return nullptr;
}

/**
 * Inserts a string into the symboltable and returns the symindex for the string.
 */
SymbolTable::SymIndex SymbolTable::Insert(const char * pStr, bool modify)
{
    for(size_t i = 0; i < this->_strings.size(); ++i) {
        if (_strings[i] == pStr) {
            return i;
        }
    }
    if (modify) {
        size_t index = _strings.size();
        _strings.push_back(pStr);
        return index;
    }
    return (SymbolTable::SymIndex) -1;
}

const char * Tokenizer::GetTokenString(Symbol_t sym)
{
    switch (sym) {
    case T_IDENT:                   return stringify(T_IDENT);
    case T_KEYWORD_IN:              return stringify(T_KEYWORD_IN);
    case T_KEYWORD_OUT:             return stringify(T_KEYWORD_OUT);
    case T_KEYWORD_NODE:            return stringify(T_KEYWORD_NODE);
    case T_KEYWORD_QUERY:           return stringify(T_KEYWORD_QUERY);
    case T_KEYWORD_EVENT:           return stringify(T_KEYWORD_EVENT);
    case T_KEYWORD_TRUE:            return stringify(T_KEYWORD_TRUE);
    case T_KEYWORD_FALSE:           return stringify(T_KEYWORD_FALSE);
    case T_TYPE_FLOAT:              return stringify(T_TYPE_FLOAT);
    case T_INTEGER:                 return stringify(T_TYPE_INTEGER);
    case T_REAL:                    return stringify(T_REAL);
    case T_ASSIGN:                  return stringify(T_ASSIGN);
    case T_QUESTION:                return stringify(T_QUESTION);
    case T_COMMA:                   return stringify(T_COMMA);
    case T_SEMICOLON:               return stringify(T_SEMICOLON);
    case T_COLON:                   return stringify(T_COLON);
    case T_DOT:                     return stringify(T_DOT);
    case T_LEFT_PAREN:              return stringify(T_LEFT_PAREN);
    case T_RIGHT_PAREN:             return stringify(T_RIGHT_PAREN);
    case T_LEFT_SQUARE_BRACKET:     return stringify(T_LEFT_SQUARE_BRACKET);
    case T_RIGHT_SQUARE_BRACKET:    return stringify(T_RIGHT_SQUARE_BRACKET);
    case T_LEFT_CURLY_BRACKET:      return stringify(T_LEFT_CURLY_BRACKET);
    case T_RIGHT_CURLY_BRACKET:     return stringify(T_RIGHT_CURLY_BRACKET);
    case T_ADD:                     return stringify(T_ADD);
    case T_SUB:                     return stringify(T_SUB);
    case T_MUL:                     return stringify(T_MUL);
    case T_DIV:                     return stringify(T_DIV);
    case T_EQUAL:                   return stringify(T_EQUAL);
    case T_LESS:                    return stringify(T_ASSIGN);
    case T_GRT:                     return stringify(T_GRT);
    case T_LEQ:                     return stringify(T_LEQ);
    case T_GEQ:                     return stringify(T_GEQ);
    case T_FAILURE:                 return stringify(T_FAILURE);
    case T_EOF:                     return stringify(T_EOF);
    default:                        return 0;
    }
}

} // namespace parser

} // namespace fuzzer