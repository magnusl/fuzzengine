#include <gtest\gtest.h>
#include <fuzzengine\parser.h>
#include <sstream>

using namespace fuzzer::parser;

static std::shared_ptr<fuzzer::parser::Statement>
ParseStatement(const char * Statement)
{
    std::stringstream str;
    str << Statement;
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    return parser.ParseStatement(token);
}

TEST(Declaration, ConstDeclaration)
{
    std::shared_ptr<fuzzer::parser::Statement> stmt;
    EXPECT_NO_THROW(stmt = ParseStatement("$variable = u32;"));
    ASSERT_EQ(Statement::STMT_DECL, stmt->GetType());

    Declaration * decl = (Declaration *) stmt.get();

    EXPECT_STREQ("variable", decl->_name.c_str());
}

TEST(Declaration, SequenceDeclaration)
{
    std::shared_ptr<fuzzer::parser::Statement> stmt;
    EXPECT_NO_THROW(stmt = ParseStatement("$x = [ u32 ];"));
    ASSERT_EQ(Statement::STMT_DECL, stmt->GetType());

    Declaration * decl = (Declaration *) stmt.get();

    EXPECT_STREQ("x", decl->_name.c_str());
}
