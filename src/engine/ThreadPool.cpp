#include "ThreadPool.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <vector>
namespace fuzzer {

class ThreadPool::Implementation
{
public:
    Implementation(size_t NumThreads)
    {
        hThreads.resize(NumThreads);
        for(size_t i = 0; i < NumThreads; ++i) {
            DWORD id;
            hThreads[i] = CreateThread(0, 0, ThreadFunc, this, 0, &id);
            if (hThreads[i] == NULL) {
                throw std::runtime_error("Failed to create thread.");
            }
        }       
    }

    std::shared_ptr<WorkItem>   GetWorkItem();

    static DWORD WINAPI ThreadFunc(LPVOID);

    std::vector<HANDLE>                         hThreads;
    std::vector<std::shared_ptr<WorkItem> >     Work;
};

DWORD WINAPI ThreadPool::Implementation::ThreadFunc(LPVOID arg)
{
    ThreadPool::Implementation * impl = (ThreadPool::Implementation *) arg;
    if (impl) {
        // as long as we can get work items
        while(std::shared_ptr<WorkItem> work = impl->GetWorkItem())
        {
            work->Execute();
        }
    }
}


} // namespace fuzzer