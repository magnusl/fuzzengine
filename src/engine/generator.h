#ifndef _AST2_H_
#define _AST2_H_

#include "bytecode.h"
#include "token.h"
#include "script.h"
#include "template.h"
#include <memory>

namespace fuzzer {

namespace bytecode {

///
/// \class  Generator
/// \brief  Bytecode generator
///
class Generator
{
public:
    std::shared_ptr<bytecode::Script> ParseScript(parser::Tokenizer &);
    std::shared_ptr<bytecode::Method> ParseMethod(parser::Tokenizer &, std::shared_ptr<Script>);
    std::shared_ptr<runtime::Template> ParseTemplate(parser::Tokenizer &);
protected:
    void ParseStatement(parser::Tokenizer &, std::shared_ptr<Method>, std::shared_ptr<Script>);
    void ParseExpression(parser::Tokenizer & tokenizer, std::shared_ptr<Method>, std::shared_ptr<Script>);
    void ParseTerm(parser::Tokenizer & tokenizer, std::shared_ptr<Method>, std::shared_ptr<Script>);
    void ParseFactor(parser::Tokenizer & tokenizer, std::shared_ptr<Method>, std::shared_ptr<Script>);
    void Expect(parser::Symbol_t, parser::Tokenizer &);
    void ParseExpression(parser::Tokenizer & tokenizer, std::shared_ptr<runtime::Template>, bool);
    void ParseTemplateExpressions(std::shared_ptr<runtime::Template>, parser::Tokenizer & tokenizer, bool fuzzed);
};

} // namespace bytecode

} // namespace fuzzer

#endif