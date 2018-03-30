#include <gtest\gtest.h>
#include <fuzzengine\parser.h>
#include <sstream>

using namespace fuzzer::parser;

///////////////////////////////////////////////////////////////////////////////
//                              Constants without value                      //
///////////////////////////////////////////////////////////////////////////////
TEST(Expression, u8NoValue)
{
    std::stringstream str;
    str << "u8";
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = parser.ParseExpression(token));

    std::shared_ptr<TypeExpression> ty =
        std::dynamic_pointer_cast<fuzzer::parser::TypeExpression>(exp);

    ASSERT_TRUE(ty != nullptr);
    EXPECT_EQ(UNSIGNED8, ty->_type);
}

TEST(Expression, u16NoValue)
{
    std::stringstream str;
    str << "u16";
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = parser.ParseExpression(token));
    
    std::shared_ptr<TypeExpression> ty =
        std::dynamic_pointer_cast<fuzzer::parser::TypeExpression>(exp);

    ASSERT_TRUE(ty != nullptr);
    EXPECT_EQ(UNSIGNED16, ty->_type);
}

TEST(Expression, u24NoValue)
{
    std::stringstream str;
    str << "u24";
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = parser.ParseExpression(token));

    std::shared_ptr<TypeExpression> ty =
        std::dynamic_pointer_cast<fuzzer::parser::TypeExpression>(exp);

    ASSERT_TRUE(ty != nullptr);
    EXPECT_EQ(UNSIGNED24, ty->_type);
}

TEST(Expression, u32NoValue)
{
    std::stringstream str;
    str << "u32";
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = parser.ParseExpression(token));
    
    std::shared_ptr<TypeExpression> ty =
        std::dynamic_pointer_cast<fuzzer::parser::TypeExpression>(exp);

    ASSERT_TRUE(ty != nullptr);
    EXPECT_EQ(UNSIGNED32, ty->_type);
}

TEST(Expression, u64NoValue)
{
    std::stringstream str;
    str << "u64";
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = parser.ParseExpression(token));
    
    std::shared_ptr<TypeExpression> ty =
        std::dynamic_pointer_cast<fuzzer::parser::TypeExpression>(exp);

    ASSERT_TRUE(ty != nullptr);
    EXPECT_EQ(UNSIGNED64, ty->_type);
}

///////////////////////////////////////////////////////////////////////////////
//                              Constants with value                         //
///////////////////////////////////////////////////////////////////////////////

TEST(Expression, u8WithValue)
{
    std::stringstream str;
    str << "u8(10)";
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = parser.ParseExpression(token));
    ASSERT_EQ(fuzzer::parser::Expression::EXP_CONSTANT, exp->GetType());
    Constant * cvar = reinterpret_cast<Constant *>(exp.get());
    EXPECT_TRUE(cvar->_hasValue);
    EXPECT_EQ(UNSIGNED8, cvar->_type);
    EXPECT_EQ(10, cvar->u.u8);
}

TEST(Expression, u16WithValue)
{
    std::stringstream str;
    str << "u16(10)";
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = parser.ParseExpression(token));
    ASSERT_EQ(fuzzer::parser::Expression::EXP_CONSTANT, exp->GetType());
    Constant * cvar = reinterpret_cast<Constant *>(exp.get());
    EXPECT_TRUE(cvar->_hasValue);
    EXPECT_EQ(UNSIGNED16, cvar->_type);
    EXPECT_EQ(10, cvar->u.u16);
}

TEST(Expression, u32WithValue)
{
    std::stringstream str;
    str << "u32(10)";
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = parser.ParseExpression(token));
    ASSERT_EQ(fuzzer::parser::Expression::EXP_CONSTANT, exp->GetType());
    Constant * cvar = reinterpret_cast<Constant *>(exp.get());
    EXPECT_TRUE(cvar->_hasValue);
    EXPECT_EQ(UNSIGNED32, cvar->_type);
    EXPECT_EQ(10, cvar->u.u32);
}

TEST(Expression, u64WithValue)
{
    std::stringstream str;
    str << "u64(10)";
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    std::shared_ptr<fuzzer::parser::Expression> exp;
    ASSERT_NO_THROW(exp = parser.ParseExpression(token));
    ASSERT_EQ(fuzzer::parser::Expression::EXP_CONSTANT, exp->GetType());
    Constant * cvar = reinterpret_cast<Constant *>(exp.get());
    EXPECT_TRUE(cvar->_hasValue);
    EXPECT_EQ(UNSIGNED64, cvar->_type);
    EXPECT_EQ(10, cvar->u.u64);
}