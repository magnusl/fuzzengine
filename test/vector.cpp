#include <gtest\gtest.h>
#include <fuzzengine\parser.h>
#include <sstream>

using namespace fuzzer::parser;

static std::shared_ptr<fuzzer::parser::Expression>
ParseExpression(const char * Expression)
{
    std::stringstream str;
    str << Expression;
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    return parser.ParseExpression(token);
}

TEST(Vector, ArrayWith100Bytes)
{
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = ParseExpression("u8<100>"));

    Vector * v = (Vector *) exp.get();
    EXPECT_EQ(100, v->_lower);
    EXPECT_EQ(100, v->_upper);
    EXPECT_EQ(UNSIGNED8, v->_type);
}

TEST(Vector, ArrayWith100to200Bytes)
{
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = ParseExpression("u8<100-200>"));

    Vector * v = (Vector *) exp.get();
    EXPECT_EQ(100, v->_lower);
    EXPECT_EQ(200, v->_upper);
    EXPECT_EQ(UNSIGNED8, v->_type);
}

TEST(Vector, ArrayWithValues)
{
    std::shared_ptr<fuzzer::parser::Expression> exp;
    EXPECT_THROW(ParseExpression("u8<3>(100, 200, 300)"), std::runtime_error);
}
