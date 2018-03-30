#ifndef _POOL_H_
#define _POOL_H_

#include <vector>

namespace fuzzer {

namespace parser {

template<class T, size_t IncrementSize>
class Pool
{
public:
    Pool() : m_nOffset(0)
    {
    }

    size_t Insert(const T * ptr, size_t count)
    {
        size_t pos = (size_t)-1;
        if (count == 0) {
            return pos;
        }
        if (m_Data.size() < (m_nOffset + count)) {
            m_Data.resize(m_Data.size() + (count < IncrementSize ? IncrementSize : count));
        }
        memcpy(&m_Data[m_nOffset], ptr, count);
        pos = m_nOffset;
        m_nOffset += count;
        return pos;
    }

    const T * GetPointer(size_t offset) const
    {
        return (offset >= m_nOffset ? nullptr : &m_Data[offset]);
    }
protected:
    std::vector<T>  m_Data;
    size_t          m_nOffset;
};

} // namespace parser

} // namespace fuzzer

#endif