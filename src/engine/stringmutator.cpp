#include "stringmutator.h"

namespace fuzzer {

namespace runtime {

static const char * bad[] = {
    "/.../.../.../.../.../.../.../.../.../.../",
    "/../../../../../../../../../../../../etc/passwd",
    "/../../../../../../../../../../../../boot.ini",
    "..:..:..:..:..:..:..:..:..:..:..:..:..:",
    "\\\\*",
    "\\\\?\\",
    "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
    "%01%02%03%04%0a%0d%0aADSF",
    "%01%02%03@%04%0a%0d%0aADSF",
    "/%00/",
    "%00/",
    "%00",
    "%u0000",
    "%\xfe\xf0%\x00\xff",
    "1;SELECT%20*",
    "'sqlattempt1",
    "(sqlattempt2)",
    "OR%201=1",
};

static size_t CommonSizes[] = {
    128,
    256,
    512,
    1024,
    2048,
    4096,
    8192,
    0xffff - 1,
    0xffff - 2,
    100000
};

StringMutator::StringMutator(const char * str) : _index(0)
{
    /// mutate the original string
    if (str) {
        _db.push_back(str);
    }

    /// known bad strings
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        _db.push_back(bad[i]);
    }
    #if 0
    /// misc strings
    for(size_t i = 0; i < sizeof(CommonSizes)/sizeof(CommonSizes[0]); ++i) {
        size_t size = CommonSizes[i];
        repeat("%s", size);
        repeat("%d", size);
        repeat("%p", size);
        repeat("\\n", size);
        repeat("A", size);
        repeat("B", size);
        repeat("<", size);
        repeat(">", size);
        repeat("%", size);
        repeat("\r\n", size);
    }
    #endif
}

void StringMutator::repeat(const char * s, size_t count)
{
    std::string str;
    for(size_t i = 0; i < count; ++i) {
        str += s;
    }
    _db.push_back(str);
}

bool StringMutator::NextString(std::string & str)
{
    if (_index < _db.size()) {
        str = _db[_index++];
        return true;
    }
    return false;
}

bool StringMutator::HasMore()
{
    return _index < _db.size();
}

}

}