#ifndef _PARSER_H_
#define _PARSER_H_

#include "ast.h"
#include "token.h"

namespace fuzzer {

namespace parser {

///
/// \class  Parser
///
class Parser
{
public:
    std::shared_ptr<Statement> ParseStatement(Tokenizer &);
    std::shared_ptr<Output> ParseOutput(Tokenizer &);
    std::shared_ptr<Input> ParseInput(Tokenizer &);
    std::shared_ptr<Declaration> ParseDeclaration(Tokenizer &);
    std::shared_ptr<Expression> ParseExpression(Tokenizer &);
    std::shared_ptr<Sequence> ParseSequence(Tokenizer &);
    std::shared_ptr<FuzzSequence> ParseFuzzySequence(Tokenizer &);
    std::shared_ptr<Reference> ParseReference(Tokenizer &, const char *);
    std::shared_ptr<Expression> ParseConstant(Tokenizer &, PrimitiveType);
    std::shared_ptr<Expression> ParseCast(Tokenizer &, PrimitiveType);
    std::shared_ptr<PropertyAccess> ParsePropertyAccess(Tokenizer &, const char *);
    std::shared_ptr<Vector> ParseVector(Tokenizer &, PrimitiveType);

protected:
    void Expect(Symbol_t, Tokenizer &);
};

} // namespace parser

} // namespace fuzzer

#endif