#include <gtest\gtest.h>
#include <fuzzengine\integermutator.h>
#include <fuzzengine\template.h>
#include <sstream>

using namespace fuzzer::runtime;
using namespace std;

TEST(IntegerMutator, Integer1)
{
    Template tp;
    UnsignedMutator<uint8_t> mutator(0);
    tp.lazy( &mutator );

    vector<uint8_t> result;
    tp.generate(result);
}