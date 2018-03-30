#ifndef _TEMPLATE_H_
#define _TEMPLATE_H_

#include <stdint.h>
#include <vector>
#include <memory>
#include "lazy.h"
#include "ast.h"
#include "mutator.h"

namespace fuzzer {

namespace runtime {

///
/// \class  Template
///
class Template
{
public:
    Template();
    virtual ~Template();

    /// sets little endian byte order
    Template & little_endian();
    /// sets big endian byte order
    Template & big_endian();

    size_t u8(uint8_t, size_t pos = ~0L);
    size_t u16(uint16_t, size_t pos = ~0L);
    size_t u24(uint32_t, size_t pos = ~0L);
    size_t u32(uint32_t, size_t pos = ~0L);
    size_t u64(uint64_t, size_t pos = ~0L);

    /// add a lazy evaluator
    size_t lazy(LazyEvaluation *, size_t pos = ~0L);

    template<class T>
    size_t array(const T * data, size_t count, size_t pos = ~0L) {
        return _array(data, sizeof(T) * count);
    };

    ///
    /// \brief  Get the registered mutators
    ///
    std::vector<Mutator *> GetMutators() const;

    ///
    /// \brief  generates data from the template
    ///
    void generate(std::vector<uint8_t> &);
    void generate(Buffer &);

protected:
    size_t _array(const void *, size_t, size_t pos = ~0L);
    
protected:
    class Implementation;
    Implementation * _impl;
};

} // namespace runtime

} // namespace fuzzer

#endif