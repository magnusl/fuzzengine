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

TEST(Output, OutputConst)
{
    std::shared_ptr<fuzzer::parser::Statement> stmt;
    EXPECT_NO_THROW(stmt = ParseStatement("<< u32;"));
    ASSERT_EQ(Statement::STMT_OUT, stmt->GetType());
}

TEST(Output, OutputSequence)
{
    std::shared_ptr<fuzzer::parser::Statement> stmt;
    EXPECT_NO_THROW(stmt = ParseStatement("<< [ u32 ];"));
    ASSERT_EQ(Statement::STMT_OUT, stmt->GetType());
}

TEST(Output, MultipleOutput)
{
    std::shared_ptr<fuzzer::parser::Statement> stmt;
    EXPECT_NO_THROW(stmt = ParseStatement("<< u32 << u8;"));
    ASSERT_EQ(Statement::STMT_OUT, stmt->GetType());
}

TEST(Output, MultipleChainedOutput)
{
    std::shared_ptr<fuzzer::parser::Statement> stmt;
    EXPECT_NO_THROW(stmt = ParseStatement("<< u32 << u8 << [u32];"));
    ASSERT_EQ(Statement::STMT_OUT, stmt->GetType());
}