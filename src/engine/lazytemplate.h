#ifndef _LAZYTEMPLATE_H_
#define _LAZYTEMPLATE_H_

#include "lazy.h"
#include "template.h"
#include <memory>

namespace fuzzer {

namespace runtime {

///
/// \class  LazyTemplateData
/// \brief  Lazy evaulator for acccessing the generated data of a template.
///
class LazyTemplateData : public LazyEvaluation
{
public:
    LazyTemplateData(std::shared_ptr<Template> & tp) : _template(tp)
    {
    }

    virtual void evaluate(Buffer & buffer)
    {
        _template->generate(buffer);
    }

protected:
    std::shared_ptr<Template> _template;
};

///
/// \class  LazyTemplateData
/// \brief  Lazy evaulator for acccessing the generated data of a template.
///
class LazyTemplateSize : public LazyEvaluation
{
public:
    LazyTemplateSize(std::shared_ptr<Template> & tp) : _template(tp)
    {
    }

    virtual void evaluate(Buffer & buffer)
    {
    }

protected:
    std::shared_ptr<Template> _template;
};

} // namespace runtime

} // namespace fuzzer

#endif