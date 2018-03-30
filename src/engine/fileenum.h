#ifndef _FILEENUM_H_
#define _FILEENUM_H_

#include <vector>
#include <string>

namespace fuzzer {

///
/// \brief  Enumerate a directory
///
bool EnumerateDirectory(const char * Directory,std::vector<std::string> & Files);

} // namespace fuzzer

#endif