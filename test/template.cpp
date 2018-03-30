#include <fuzzengine\template.h>
#include <gtest\gtest.h>
#include <fuzzengine\parser.h>

using namespace fuzzer::parser;
using namespace std;

TEST(Template, SingleValue_BigEndian)
{
    fuzzer::runtime::Template t;
    EXPECT_EQ(0, t.u32(0xDEADBEEF));

    vector<uint8_t> dst;    
    EXPECT_NO_THROW(t.generate(dst));
    ASSERT_EQ(4, dst.size());
    EXPECT_EQ(0xDE, dst[0]);
    EXPECT_EQ(0xAD, dst[1]);
    EXPECT_EQ(0xBE, dst[2]);
    EXPECT_EQ(0xEF, dst[3]);
}

TEST(Template, SingleValue_LittleEndian)
{
    fuzzer::runtime::Template t;
    EXPECT_EQ(0, t.u32(0xDEADBEEF));

    vector<uint8_t> dst;    
    EXPECT_NO_THROW(t.little_endian().generate(dst));
    ASSERT_EQ(4, dst.size());
    EXPECT_EQ(0xDE, dst[3]);
    EXPECT_EQ(0xAD, dst[2]);
    EXPECT_EQ(0xBE, dst[1]);
    EXPECT_EQ(0xEF, dst[0]);
}

TEST(Template, ReplaceSingle_BigEndian)
{
    fuzzer::runtime::Template t;
    EXPECT_EQ(0, t.u32(0xDEADBEEF));
    EXPECT_EQ(0, t.u32(0xBEEFBEEF, 0));

    vector<uint8_t> dst;    
    EXPECT_NO_THROW(t.generate(dst));
    ASSERT_EQ(4, dst.size());

    EXPECT_EQ(0xBE, dst[0]);
    EXPECT_EQ(0xEF, dst[1]);
    EXPECT_EQ(0xBE, dst[2]);
    EXPECT_EQ(0xEF, dst[3]);
}

TEST(Template, TwoValues_BigEndian)
{
    fuzzer::runtime::Template t;
    EXPECT_EQ(0, t.u32(0xDEADBEEF));
    EXPECT_EQ(1, t.u32(0xBEEFBABE));

    vector<uint8_t> dst;    
    EXPECT_NO_THROW(t.generate(dst));
    ASSERT_EQ(8, dst.size());

    EXPECT_EQ(0xDE, dst[0]);
    EXPECT_EQ(0xAD, dst[1]);
    EXPECT_EQ(0xBE, dst[2]);
    EXPECT_EQ(0xEF, dst[3]);
    EXPECT_EQ(0xBE, dst[4]);
    EXPECT_EQ(0xEF, dst[5]);
    EXPECT_EQ(0xBA, dst[6]);
    EXPECT_EQ(0xBE, dst[7]);
}

TEST(Template, Data)
{
    const uint8_t data[] = {0xde, 0xad, 0xbe, 0xef};
    fuzzer::runtime::Template t;
    EXPECT_EQ(0, t.array<uint8_t>(data, sizeof(data)));

    vector<uint8_t> dst;    
    EXPECT_NO_THROW(t.generate(dst));
    ASSERT_EQ(4, dst.size());

    EXPECT_EQ(0xDE, dst[0]);
    EXPECT_EQ(0xAD, dst[1]);
    EXPECT_EQ(0xBE, dst[2]);
    EXPECT_EQ(0xEF, dst[3]);
}