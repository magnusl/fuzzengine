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

TEST(Sequence, EmptySequence)
{
    std::shared_ptr<fuzzer::parser::Expression> exp;
    EXPECT_THROW(exp = ParseExpression("[]"), std::runtime_error);
}

TEST(Sequence, SingleElementSequence)
{
    std::shared_ptr<fuzzer::parser::Expression> exp;
    EXPECT_NO_THROW(exp = ParseExpression("[u8]"));
    ASSERT_EQ(Expression::EXP_SEQUENCE, exp->GetType());

    Sequence * seq = (Sequence *) exp.get();
    ASSERT_EQ(1, seq->_expressions.size());
    EXPECT_EQ(seq->_expressions.front()->GetType(), Expression::EXP_TYPE);
}

TEST(Sequence, SequenceWithMultipleConstants)
{
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = ParseExpression("[u8, u32, u16, u24]"));
    ASSERT_EQ(Expression::EXP_SEQUENCE, exp->GetType());

    Sequence * seq = (Sequence *) exp.get();
    ASSERT_EQ(4, seq->_expressions.size());
}

TEST(Sequence, SequenceWithVector)
{
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = ParseExpression("[u8<100>]"));
    ASSERT_EQ(Expression::EXP_SEQUENCE, exp->GetType());

    Sequence * seq = (Sequence *) exp.get();
    ASSERT_EQ(1, seq->_expressions.size());
}

TEST(Sequence, SequenceWithSingleFuzzedElement)
{
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = ParseExpression("[{ u8 }]"));
    ASSERT_EQ(Expression::EXP_SEQUENCE, exp->GetType());
    Sequence * seq = (Sequence *) exp.get();
    ASSERT_EQ(1, seq->_expressions.size());
}

TEST(Sequence, SequenceWithMultipleFuzzedElement)
{
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = ParseExpression("[{ u8, u32, u16 }]"));
    ASSERT_EQ(Expression::EXP_SEQUENCE, exp->GetType());
    Sequence * seq = (Sequence *) exp.get();
    ASSERT_EQ(1, seq->_expressions.size());
}