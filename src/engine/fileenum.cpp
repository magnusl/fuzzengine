#include "fileenum.h"
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif
#include <sstream>

namespace fuzzer {

///
/// \brief  Enumerate a directory
///
bool EnumerateDirectory(const char * Directory,std::vector<std::string> & Files)
{
    std::stringstream ss;
    ss << Directory;
    ss << "\\*";

    WIN32_FIND_DATAA data;
    HANDLE hFind = FindFirstFileA(ss.str().c_str(), &data);
    if (hFind == INVALID_HANDLE_VALUE) {
        return false;
    }

    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            if ((data.nFileSizeHigh != 0) || (data.nFileSizeLow != 0)) {
                std::string name = data.cFileName;
                Files.push_back(name);
            }
        }
    } while(FindNextFileA(hFind, &data));

    FindClose(hFind);
    return true;
}

}