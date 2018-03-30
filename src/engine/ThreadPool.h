#ifndef _THREADPOOL_H_
#define _THREADPOOL_H_

#include <memory>

namespace fuzzer {

///
/// \class  WorkItem
///
class WorkItem
{
public:
    virtual bool Execute() = 0;
};

///
/// \class  ThreadPool
///
class ThreadPool
{
public:
    ThreadPool(size_t NumThreads);
    ~ThreadPool();
    
    ///
    /// \brief  Submits a work item
    ///
    void submit(std::shared_ptr<WorkItem> & Work);

private:
    class Implementation;
    std::unique_ptr<Implementation> _impl;
};

} // namespace fuzzer

#endif
