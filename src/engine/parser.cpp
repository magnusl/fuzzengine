#include "parser.h"
#include <sstream>

namespace fuzzer {

namespace parser {

///
/// \brief  Translates a token to the corresponding primitive type
///
static PrimitiveType tok2prim(Symbol_t token)
{
    switch(token) {
    case T_KEYWORD_U8:  return UNSIGNED8;
    case T_KEYWORD_U16: return UNSIGNED16;
    case T_KEYWORD_U24: return UNSIGNED24;
    case T_KEYWORD_U32: return UNSIGNED32;
    case T_KEYWORD_U64: return UNSIGNED64;
    case T_KEYWORD_S8:  return SIGNED8;
    case T_KEYWORD_S16: return SIGNED16;
    case T_KEYWORD_S24: return SIGNED24;
    case T_KEYWORD_S32: return SIGNED32;
    case T_KEYWORD_S64: return SIGNED64;
    default:
        throw std::runtime_error("Token does not represent a primitive type.");
    }
}

void Parser::Expect(Symbol_t sym, Tokenizer & tokenizer)
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

///
/// \brief  Parses an expression
///
std::shared_ptr<Expression> Parser::ParseExpression(Tokenizer & tokenizer)
{
    Symbol_t token = tokenizer.GetSym();
    switch(token) {
    case T_LEFT_SQUARE_BRACKET:
        return ParseSequence(tokenizer);
    case T_LEFT_CURLY_BRACKET:
        /// { ... } , fuzzed sequence
        return ParseFuzzySequence(tokenizer);
    case T_KEYWORD_U8:
    case T_KEYWORD_U16:
    case T_KEYWORD_U24:
    case T_KEYWORD_U32:
    case T_KEYWORD_U64:
    case T_KEYWORD_S8:
    case T_KEYWORD_S16:
    case T_KEYWORD_S24:
    case T_KEYWORD_S32:
    case T_KEYWORD_S64:
        if (tokenizer.Peek() == T_LESS) {
            /// < ... > , vector
            return ParseVector(tokenizer, tok2prim(token));
        } else if (tokenizer.Peek() == T_LEFT_PAREN) {
            /// constant, or cast expression
            Expect(T_LEFT_PAREN, tokenizer);
            if (tokenizer.Peek() == T_DOLLARSIGN) {
                /// u32($...) , cast expression
                std::shared_ptr<Expression> exp = ParseCast(tokenizer, tok2prim(token));
                Expect(T_RIGHT_PAREN, tokenizer);
                return exp;
            } else {
                /// u32(10) , constant with type and default value
                std::shared_ptr<Expression> exp = ParseConstant(tokenizer, tok2prim(token));
                Expect(T_RIGHT_PAREN, tokenizer);
                return exp;
            }
        } else {
            /// u32 , type with no default value
            return std::make_shared<TypeExpression>(tok2prim(token));
        }
        break;
    case T_DOLLARSIGN:
        Expect(T_IDENT, tokenizer);
        if (const char * name = tokenizer.SymbolTable().Retrive(tokenizer.SymIndex())) {
            if (tokenizer.Peek() == T_DOT) {
                /// $varible. , property access
                return ParsePropertyAccess(tokenizer, name);
            } else {
                /// $variable
                return ParseReference(tokenizer, name);
            }
        } else {
            throw std::runtime_error("Failed to get variable name from symbol table.");
        }
        break;
    }
    throw std::runtime_error("Unknown expression.");
}

std::shared_ptr<Sequence> Parser::ParseSequence(Tokenizer & tokenizer)
{
    ///
    /// list of comma separated expressions
    ///
    std::shared_ptr<Sequence> sequence = std::make_shared<Sequence>();
    Symbol_t sym;
    do {
        sequence->_expressions.push_back( ParseExpression(tokenizer) );
        sym = tokenizer.GetSym();
    } while( sym == T_COMMA );

    if (sym != T_RIGHT_SQUARE_BRACKET) {
        throw std::runtime_error("Expected T_RIGHT_SQUARE_BRACKET to terminate sequence.");
    }
    return sequence;
}

std::shared_ptr<FuzzSequence> Parser::ParseFuzzySequence(Tokenizer & tokenizer)
{
    std::shared_ptr<FuzzSequence> sequence = std::make_shared<FuzzSequence>();
    Symbol_t sym;
    do {
        sequence->_expressions.push_back( ParseExpression(tokenizer) );
        sym = tokenizer.GetSym();
    } while( sym == T_COMMA );

    if (sym != T_RIGHT_CURLY_BRACKET) {
        throw std::runtime_error("Expected T_RIGHT_CURLY_BRACKET to terminate fuzzed sequence.");
    }
    return sequence;
}

std::shared_ptr<Expression> Parser::ParseConstant(Tokenizer & tokenizer,
    PrimitiveType primType)
{   
    std::shared_ptr<Constant> constValue = std::make_shared<Constant>();
    constValue->_type       = primType;
    constValue->_hasValue   = true;

    switch(primType)
    {
    case UNSIGNED8:
        Expect(T_INTEGER, tokenizer);
        if (tokenizer.IntValue() > std::numeric_limits<uint8_t>::max()) {
            throw std::runtime_error("Byte constant is to large.");
        }
        constValue->u.u8 = static_cast<uint8_t>(tokenizer.IntValue());
        break;
    case UNSIGNED16:
        Expect(T_INTEGER, tokenizer);
        if (tokenizer.IntValue() > std::numeric_limits<uint16_t>::max()) {
            throw std::runtime_error("Word constant is to large.");
        }
        constValue->u.u16 = static_cast<uint16_t>(tokenizer.IntValue());
        break;
    case UNSIGNED32:
        Expect(T_INTEGER, tokenizer);
        if (tokenizer.IntValue() > std::numeric_limits<uint32_t>::max()) {
            throw std::runtime_error("Dword constant is to large.");
        }
        constValue->u.u32 = static_cast<uint32_t>(tokenizer.IntValue());
        break;
    case UNSIGNED64:
        Expect(T_INTEGER, tokenizer);
        if (tokenizer.IntValue() > std::numeric_limits<uint64_t>::max()) {
            throw std::runtime_error("Qword constant is to large.");
        }
        constValue->u.u64 = static_cast<uint64_t>(tokenizer.IntValue());
        break;
    default:
        throw std::runtime_error("Suppport for type not implemented yet.");
        break;
    }
    return constValue;
}

std::shared_ptr<Expression> Parser::ParseCast(Tokenizer & tokenizer,
    PrimitiveType primType)
{
    std::shared_ptr<Expression> exp = ParseExpression(tokenizer);
    switch(exp->GetType())
    {
    case Expression::EXP_REFERENCE:
        {
            throw std::runtime_error("Casting references hasn't been implemented.");
        }
    case Expression::EXP_PROP_ACCESS:
        {
            throw std::runtime_error("Casting properties hasn't been implemented.");
        }
    default:
        throw std::runtime_error("Cannot cast expression.");
    }
}

///
/// \brief  Parses a reference to a variable
///
std::shared_ptr<Reference> Parser::ParseReference(Tokenizer & tokenizer,
    const char * Name)
{
    if (!Name) {
        throw std::runtime_error("Invalid NULL argument to ParseReference.");
    }
    std::shared_ptr<Reference> ref = std::make_shared<Reference>();
    ref->_name = Name;
    return ref;
}

///
/// \brief  Parses a reference to a property
///
std::shared_ptr<PropertyAccess> Parser::ParsePropertyAccess(Tokenizer & tokenizer,
    const char * Name)
{
    if (!Name) {
        throw std::runtime_error("Invalid NULL argument to ParsePropertyAccess.");
    }
    Expect(T_DOT, tokenizer);
    Expect(T_IDENT, tokenizer);

    const char * propName = tokenizer.SymbolTable().Retrive(tokenizer.SymIndex());
    if (!propName) {
        throw std::runtime_error("Failed to get string from symbol table.");
    }

    std::shared_ptr<PropertyAccess> propAccess = std::make_shared<PropertyAccess>();
    propAccess->_name       = Name;
    propAccess->_propname   = propName;
    
    return propAccess; 
}

///
/// u32<100-200>(....)
/// u8<8>(1,2,3,4,5,6,7,8)
///
std::shared_ptr<Vector> Parser::ParseVector(Tokenizer & tokenizer,
    PrimitiveType type)
{
    Expect( T_LESS, tokenizer );
    Expect( T_INTEGER, tokenizer );
    int lower = tokenizer.IntValue();
    int upper = lower;
    
    Symbol_t sym = tokenizer.GetSym();
    if (sym == T_GRT) {
        /// u8<100>
    } else if (sym == T_SUB) {
        /// u8<100-200>
        Expect( T_INTEGER, tokenizer);
        upper = tokenizer.IntValue();
        Expect(T_GRT, tokenizer);
    } else {
        throw std::runtime_error("Unexpected token.");
    }
    if (tokenizer.Peek() == T_LEFT_PAREN) {
        /// u8<..>()
        // Not supported yet
        throw std::runtime_error("Support for vector values is unsupported.");
    }
    std::shared_ptr<Vector> vec = std::make_shared<Vector>();
    vec->_type  = type;
    vec->_lower = lower;
    vec->_upper = upper;

    return vec;
}

std::shared_ptr<Statement> Parser::ParseStatement(Tokenizer & tokenizer)
{
    Symbol_t sym = tokenizer.Peek();
    if (sym == T_DOLLARSIGN) {
        /// $variable = expression, a declaration
        return ParseDeclaration(tokenizer);
    } else if (sym == T_OUTPUT) {
        /// "<<" , output statement
        return ParseOutput(tokenizer);
    } else if (sym == T_LEFT_SQUARE_BRACKET) {
        /// [sequence] >> $variable, input statement
        return ParseInput(tokenizer);
    } else {
        throw std::runtime_error("Unknown statement."); 
    }
}

///
/// \brief  [ << expression ]+
///
std::shared_ptr<Output> Parser::ParseOutput(Tokenizer & tokenizer)
{
    std::shared_ptr<Output> output = std::make_shared<Output>();

    Expect(T_OUTPUT, tokenizer);

    output->_expressions.push_back(ParseExpression(tokenizer));

    while(tokenizer.Peek() == T_OUTPUT) {
        Expect(T_OUTPUT, tokenizer);
        output->_expressions.push_back(ParseExpression(tokenizer));
    }
    Expect(T_SEMICOLON, tokenizer);
    return output;
}

///
/// \brief  [...] >> $variable
///
std::shared_ptr<Input> Parser::ParseInput(Tokenizer & tokenizer)
{
    Expect(T_LEFT_SQUARE_BRACKET, tokenizer);
    
    std::shared_ptr<Input> input = std::make_shared<Input>();
    input->_input = ParseSequence(tokenizer);
    Expect(T_INPUT, tokenizer);

    Expect(T_DOLLARSIGN, tokenizer);
    Expect(T_IDENT, tokenizer);

    const char * name = tokenizer.SymbolTable().Retrive(tokenizer.SymIndex());
    if (!name) {
        throw std::runtime_error("Failed to get identifier name from symbol table.");
    }

    input->_name = name;
    return input;
}

///
/// \brief  $variable = expression
///
std::shared_ptr<Declaration> Parser::ParseDeclaration(Tokenizer & tokenizer)
{
    Expect(T_DOLLARSIGN, tokenizer);
    Expect(T_IDENT, tokenizer);

    const char * identifier = tokenizer.SymbolTable().Retrive(tokenizer.SymIndex());
    if (!identifier) {
        throw std::runtime_error("Failed to get identifier name from symbol table.");
    }

    Expect(T_ASSIGN, tokenizer);

    std::shared_ptr<Expression> exp = ParseExpression(tokenizer);
    Expect(T_SEMICOLON, tokenizer);

    std::shared_ptr<Declaration> decl = std::make_shared<Declaration>();
    decl->_value = exp;
    decl->_name = identifier;
    return decl;
}

}

} 