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

TEST(Reference, VariableReference)
{
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = ParseExpression("$variable"));
    ASSERT_EQ(Expression::EXP_REFERENCE, exp->GetType());

    Reference * ref = (Reference *) exp.get();
    EXPECT_STRCASEEQ("variable", ref->_name.c_str());
}

TEST(Reference, PropertyAccess)
{
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = ParseExpression("$variable.length"));
    ASSERT_EQ(Expression::EXP_PROP_ACCESS, exp->GetType());

    PropertyAccess * ref = (PropertyAccess *) exp.get();
    EXPECT_STRCASEEQ("variable", ref->_name.c_str());
    EXPECT_STRCASEEQ("length", ref->_propname.c_str());
}