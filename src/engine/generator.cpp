#include "generator.h"
#include "parser.h"
#include "integermutator.h"
#include "stringmutator.h"
#include <sstream>

using namespace std;
using namespace fuzzer::parser;

namespace fuzzer {

namespace bytecode {

///
/// \brief   Parses a script file
///
shared_ptr<Script> Generator::ParseScript(parser::Tokenizer & tokenizer)
{
    shared_ptr<Script> script = make_shared<Script>();
    Symbol_t token = tokenizer.Peek();
    while(token != T_EOF) {
        if (token == T_TEMPLATE) { // template x = []
            tokenizer.GetSym();
            Expect(T_IDENT, tokenizer);
            SymbolTable::SymIndex template_name = tokenizer.SymIndex();
            Expect(T_ASSIGN, tokenizer);
            shared_ptr<runtime::Template> tp = ParseTemplate(tokenizer);
            Expect(T_SEMICOLON, tokenizer);

            const std::string name = tokenizer.SymbolTable().Retrive(template_name);
            if (script->_templates.find(name) != script->_templates.end()) {
                throw std::runtime_error("Duplicate template declarations.");
            }
            script->_templates[name] = tp;
        } else if (token == T_FUNCTION) { // function x() {}
            script->_methods.push_back(ParseMethod(tokenizer, script));
        } else {
            throw std::runtime_error("Unknown token.");
        }
        token = tokenizer.Peek();
    }
    return script;
}

///
/// \brief  Parses a method
///         function x(a, b) {}
///
shared_ptr<Method> Generator::ParseMethod(parser::Tokenizer & tokenizer, std::shared_ptr<Script> script)
{
    shared_ptr<Method> method = make_shared<Method>();

    Expect(T_FUNCTION, tokenizer);
    Expect(T_IDENT, tokenizer);

    method->name_index      = tokenizer.SymIndex();
    method->num_locals      = 0;
    method->method_index    = script->_methods.size();

    method->name = tokenizer.SymbolTable().Retrive(method->name_index);

    Expect(T_LEFT_PAREN, tokenizer);
    Symbol_t token = tokenizer.Peek();
    if (token != T_RIGHT_PAREN) { // one or more arguments
        do {
            Expect(T_IDENT, tokenizer);
            method->arguments.push_back(tokenizer.SymIndex());
            token = tokenizer.Peek();
            if (token == T_COMMA) {
                Expect(T_COMMA, tokenizer);
            } else {
                break;
            }
        } while(1);
    }
    Expect(T_RIGHT_PAREN, tokenizer);
    Expect(T_LEFT_CURLY_BRACKET, tokenizer);

    ///
    /// Parse the statements
    ///
    token = tokenizer.Peek();
    while(token != T_RIGHT_CURLY_BRACKET) {
        ParseStatement(tokenizer, method, script);
        token = tokenizer.Peek();
    }
    Expect(T_RIGHT_CURLY_BRACKET, tokenizer);

    return method;
}

///
/// \brief  Parses a statement
///
void Generator::ParseStatement(parser::Tokenizer & tokenizer,
    std::shared_ptr<Method> method,
    std::shared_ptr<Script> script)
{
    Symbol_t sym = tokenizer.Peek();
    if (sym == T_VAR) {
        /// var x = ...
        Expect(T_VAR, tokenizer);   // consume
        Expect(T_IDENT, tokenizer);
        SymbolTable::SymIndex variable_name = tokenizer.SymIndex(); // get variable name
        Expect(T_ASSIGN, tokenizer);
        ParseExpression(tokenizer, method, script);
        Expect(T_SEMICOLON, tokenizer);
        /// assign a id
        size_t id = method->num_locals++;
        method->locals[variable_name] = id;
        /// generate assignment
        method->ins.push_back(set_local(id));
    } else if (sym == T_IDENT) {
        /// x();
        ParseExpression(tokenizer, method, script);     //< expression will result in a value on the stack
        Expect(T_SEMICOLON, tokenizer);
        method->ins.push_back(pop());       //< pop unused value
    } else if (sym == T_RETURN) {
        Expect(T_RETURN, tokenizer);
        ParseExpression(tokenizer, method, script);
        Expect(T_SEMICOLON, tokenizer);
        method->ins.push_back(returnvalue());
    } else {
        throw std::runtime_error("Unknown token.");
    }
}

void Generator::ParseExpression(parser::Tokenizer & tokenizer,
    std::shared_ptr<Method> method,
    std::shared_ptr<Script> script)
{
    Symbol_t sym = tokenizer.Peek();
    if (sym == T_ADD) {
        Expect(T_ADD, tokenizer);   // consume and ignore
    } else if (sym == T_SUB) {
        // negate
    }

    ParseTerm(tokenizer, method, script);
    sym = tokenizer.Peek();
    if (sym == T_ADD || sym == T_SUB) {
        tokenizer.GetSym();
        ParseTerm(tokenizer, method, script);
        method->ins.push_back(sym == T_ADD ? add() : sub());
    }
}

void Generator::ParseTerm(parser::Tokenizer & tokenizer,
    std::shared_ptr<Method> method,
    std::shared_ptr<Script> script)
{
    ParseFactor(tokenizer, method, script);
    Symbol_t sym = tokenizer.Peek();
    if (sym == T_MUL || sym == T_DIV) {
        tokenizer.GetSym();
        ParseTerm(tokenizer, method, script);
        method->ins.push_back(sym == T_MUL ? mul() : div());
    }
}

void Generator::ParseFactor(parser::Tokenizer & tokenizer,
    std::shared_ptr<Method> method,
    std::shared_ptr<Script> script)
{
    Symbol_t sym = tokenizer.GetSym();
    if (sym == T_IDENT) {
        SymbolTable::SymIndex name = tokenizer.SymIndex();
        sym = tokenizer.Peek();
        if (sym == T_LEFT_PAREN) {
            ///
            /// function call
            ///
            shared_ptr<Method> called = script->findMethod(name);
            size_t parameter_count = 0;
            Expect(T_LEFT_PAREN, tokenizer);
            sym = tokenizer.Peek();
            while(sym != T_RIGHT_PAREN) {
                ParseExpression(tokenizer, method, script);
                ++parameter_count;
                sym = tokenizer.Peek();
                if (sym != T_COMMA) {
                    break;
                }
                sym = tokenizer.GetSym();
            }
            Expect(T_RIGHT_PAREN, tokenizer);
            if (called) {
                // calling a method defined in the script
                if (parameter_count != called->arguments.size()) {
                    throw std::runtime_error("Called with incorrect number of parameters.");
                }
                method->ins.push_back(call(called->method_index));
            } else {
                // calling a runtime method
                if (const char * str = tokenizer.SymbolTable().Retrive(name)) {
                    method->ins.push_back(
                        call_external(method->constant_strings.size(), parameter_count));
                    method->constant_strings.push_back( str );
                } else {
                    throw std::runtime_error("Failed to retrive constant string value.");
                }
            }
        } else {
            ///
            /// identifier
            ///
            map<size_t, size_t>::iterator it = method->locals.find(name);
            if (it != method->locals.end()) {
                /// reference to a local variable, which are stored after the arguments
                method->ins.push_back(get_local(it->second));
            } else {
                /// check arguments
                for(size_t i = 0; i < method->arguments.size(); ++i) {
                    if (method->arguments[i] == name) {
                        method->ins.push_back(get_argument(i));
                        return;
                    }
                }
                const std::string strName = tokenizer.SymbolTable().Retrive(name);
                /// check global templates
                if (script->_templates.find(strName) != script->_templates.end()) {
                    method->ins.push_back(get_template(method->constant_strings.size()));
                    method->constant_strings.push_back(strName);
                    return;
                }
                throw std::runtime_error("Unknown identifier.");
            }
        }
    } else if (sym == T_INTEGER) {
        method->ins.push_back(push_int(method->constant_ints.size()));
        method->constant_ints.push_back(tokenizer.IntValue());
    } else if (sym == T_STRING) {
        SymbolTable::SymIndex name = tokenizer.SymIndex();
        if (const char * str = tokenizer.SymbolTable().Retrive(name)) {
            method->ins.push_back(push_string(method->constant_strings.size()));
            method->constant_strings.push_back( str );
        } else {
            throw std::runtime_error("Failed to retrive constant string value.");
        }
    } else {
        throw std::runtime_error("Unknown factor");
    }
}

void Generator::Expect(Symbol_t sym, Tokenizer & tokenizer)
{   
    Symbol_t actual = tokenizer.GetSym();
    if (actual != sym) {
        std::stringstream ss;
        if (const char * str = tokenizer.GetTokenString(actual)) {
            ss << "Unexpected token \"" << str << "\" at row: " << tokenizer.Position().Row << " col: " << tokenizer.Position().Col;
        } else {
            ss << "Unkown token at row: " << tokenizer.Position().Row << " col: " << tokenizer.Position().Col;
        }
        throw std::runtime_error(ss.str());
    }
}

///////////////////////////////////////////////////////////////////////////////
//                                  Template                                 //
///////////////////////////////////////////////////////////////////////////////

std::shared_ptr<runtime::Template> Generator::ParseTemplate(
    parser::Tokenizer & tokenizer)
{
    std::shared_ptr<runtime::Template> tp = std::make_shared<runtime::Template>();
    Expect(T_LEFT_SQUARE_BRACKET, tokenizer);
    ParseTemplateExpressions(tp, tokenizer, false);
    Expect(T_RIGHT_SQUARE_BRACKET, tokenizer);
    return tp;
}

void Generator::ParseTemplateExpressions(
    std::shared_ptr<runtime::Template> tp,
    parser::Tokenizer & tokenizer,
    bool fuzzed)
{
    Symbol_t sym = T_EOF;
    do {
        sym = tokenizer.Peek();
        if (sym == T_LEFT_CURLY_BRACKET) {
            if (fuzzed) {
                throw std::runtime_error("Fuzzed sequence inside a fuzzed sequence.");
            }
            Expect(T_LEFT_CURLY_BRACKET, tokenizer);
            ParseTemplateExpressions(tp, tokenizer, true);
            Expect(T_RIGHT_CURLY_BRACKET, tokenizer);
        } else {
            ParseExpression(tokenizer, tp, fuzzed);
        }
        sym = tokenizer.Peek();
        if (sym == T_COMMA) {
            tokenizer.GetSym();     // consume T_COMMA
        } else {
            break; // end of comma separated expressions
        }
    } while(1);
}

static void AddFuzzedUInteger(Symbol_t sym, int value, std::shared_ptr<runtime::Template> tp)
{
    switch(sym) {
    case T_KEYWORD_BYTE:    tp->lazy(new runtime::UnsignedMutator<uint8_t>(value)); break;
    case T_KEYWORD_WORD:    tp->lazy(new runtime::UnsignedMutator<uint16_t>(value)); break;
    case T_KEYWORD_DWORD:   tp->lazy(new runtime::UnsignedMutator<uint32_t>(value)); break;
    case T_KEYWORD_QWORD:   tp->lazy(new runtime::UnsignedMutator<uint64_t>(value)); break;
    default:                break;
    }
}

static void AddUInteger(Symbol_t sym, int value, std::shared_ptr<runtime::Template> tp)
{
    switch(sym) {
    case T_KEYWORD_BYTE:    tp->u8(static_cast<uint8_t>(value)); break;
    case T_KEYWORD_WORD:    tp->u16(static_cast<uint16_t>(value)); break;
    case T_KEYWORD_DWORD:   tp->u32(static_cast<uint32_t>(value)); break;
    case T_KEYWORD_QWORD:   tp->u64(static_cast<uint64_t>(value)); break;
    default:                break;
    }
}

void Generator::ParseExpression(parser::Tokenizer & tokenizer,
    std::shared_ptr<runtime::Template> tp,
    bool fuzzed)
{
    Symbol_t type_sym = tokenizer.Peek();
    switch(type_sym) {
    case T_KEYWORD_BYTE:
    case T_KEYWORD_WORD:
    case T_KEYWORD_DWORD:
    case T_KEYWORD_QWORD:
        {
            tokenizer.GetSym();
            int value = 0;
            if (tokenizer.Peek() == T_LEFT_PAREN) {
                /// [ word(...) , ... 
                Expect(T_LEFT_PAREN, tokenizer);
                Expect(T_INTEGER, tokenizer);
                value = tokenizer.IntValue();
                Expect(T_RIGHT_PAREN, tokenizer);
            }
            return fuzzed ? AddFuzzedUInteger(type_sym, value, tp) : AddUInteger(type_sym, value, tp);
        }
        break;
    case T_KEYWORD_CSTRING:
    case T_KEYWORD_LINE:
        {
            /// Null terminated string
            tokenizer.GetSym();
            const char * str = 0;
            if (tokenizer.Peek() == T_LEFT_PAREN) {
                Expect(T_LEFT_PAREN, tokenizer);
                Expect(T_STRING, tokenizer);
                str = tokenizer.SymbolTable().Retrive(tokenizer.SymIndex());
                Expect(T_RIGHT_PAREN, tokenizer);
            }
            if (type_sym == T_KEYWORD_CSTRING) {
                tp->lazy(new runtime::AsciiStringMutator(runtime::AsciiStringMutator::CSTRING, str));
            } else {
                tp->lazy(new runtime::AsciiStringMutator(runtime::AsciiStringMutator::LINE, str));
            }
        }
    case T_KEYWORD_PASCAL_STRING:
        break;
    case T_KEYWORD_ARRAY:
        {
            /// array<byte>(0-256)
            tokenizer.GetSym();
            Expect(T_LESS, tokenizer);
            Symbol_t type = tokenizer.GetSym();
            if (type != T_KEYWORD_BYTE && type != T_KEYWORD_WORD && type != T_KEYWORD_DWORD && type != T_KEYWORD_QWORD) {
                throw std::runtime_error("Expected a type.");
            }
            Expect(T_GRT, tokenizer);
            Expect(T_LEFT_PAREN, tokenizer);
            Expect(T_INTEGER, tokenizer);
            int lower = tokenizer.IntValue();
            int upper = lower;
            if (tokenizer.Peek() == T_SUB) {
                if (!fuzzed) {
                    throw std::runtime_error("Variable length arrays are only allowed for fuzzed arrays.");
                }
                Expect(T_SUB, tokenizer);
                Expect(T_INTEGER, tokenizer);
                upper = tokenizer.IntValue();
            }
            Expect(T_RIGHT_PAREN, tokenizer);
            if (fuzzed) {
                
            } else {
                
            }
            break;
        }
    default:
        throw std::runtime_error("Unexpected token.");
    }
}

} // namespace bytecode

} // namespace fuzzer
