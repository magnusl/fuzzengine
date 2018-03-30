#include <gtest\gtest.h>
#include <fuzzengine\parser.h>
#include <fuzzengine\input.h>
#include <fuzzengine\arraysource.h>
#include <sstream>

using namespace fuzzer::parser;

#if 0
static std::shared_ptr<fuzzer::parser::Statement>
ParseStatement(const char * Statement)
{
    std::stringstream str;
    str << Statement;
    fuzzer::parser::Tokenizer token(str);
    fuzzer::parser::Parser parser;
    return parser.ParseStatement(token);
}

TEST(Output, inputConst)
{
    std::shared_ptr<fuzzer::parser::Statement> stmt;
    ASSERT_NO_THROW(stmt = ParseStatement("[u32, u8] >> $variable;"));
    ASSERT_EQ(Statement::STMT_IN, stmt->GetType());
}

TEST(Input, VariableArray)
{
    const uint8_t data[] = {
        0x0a,                           // length = 10 bytes
        0x01, 0x02, 0x03, 0x04, 0x05,   // 10 bytes of payload
        0x06, 0x07, 0x08, 0x09, 0x0a
    };

    fuzzer::io::ArraySource source(data, sizeof(data));
    fuzzer::io::Input input;
    /// the message starts with a byte length
    size_t lengthField = input.u8();
    /// read the payload, up to 64 bytes
    size_t payload = input.varray(lengthField, 64);
    /// now try to actually read the packet
    EXPECT_TRUE(input.read(source));

    const fuzzer::io::InputItem * item = input.get(lengthField);
    ASSERT_TRUE(item != NULL);
    EXPECT_EQ(fuzzer::io::InputItem::BYTE, item->type);
    EXPECT_EQ(10, item->u.byte);
}

TEST(Input, InvalidVariableArray)
{
    const uint8_t data[] = {
        0x0a,                           // length = 10 bytes
        0x01, 0x02, 0x03, 0x04, 0x05,   // 9 bytes of payload
        0x06, 0x07, 0x08, 0x09
    };

    fuzzer::io::ArraySource source(data, sizeof(data));
    fuzzer::io::Input input;
    /// the message starts with a byte length
    size_t lengthField = input.u8();
    /// read the payload, up to 64 bytes
    size_t payload = input.varray(lengthField, 64);
    /// now try to actually read the packet
    EXPECT_FALSE(input.read(source));
}
#endif