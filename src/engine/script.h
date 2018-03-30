#ifndef _SCRIPT_H_
#define _SCRIPT_H_

#include "bytecode.h"
#include "template.h"
#include <vector>
#include <memory>

namespace fuzzer {

namespace bytecode {

///
/// \class  Script
///
struct Script
{
    ///
    /// \brief  Return the index to the method matching the name
    ///
    std::shared_ptr<bytecode::Method> findMethod(size_t NameIndex)
    {
        for(size_t i = 0; i <_methods.size(); ++i) {
            if (_methods[i]->name_index == NameIndex) {
                return _methods[i];
            }
        }
        return nullptr;
    }

    std::shared_ptr<bytecode::Method> findMethod(const std::string & Name) const
    {
        for(size_t i = 0; i <_methods.size(); ++i) {
            if (_methods[i]->name == Name) {
                return _methods[i];
            }
        }
        return nullptr;
    }

    std::vector<std::shared_ptr<bytecode::Method> >             _methods;
    std::map<std::string, std::shared_ptr<runtime::Template> >  _templates;
};

} // namespace bytecode

} // namespace fuzzer

#endif