#include "tmpfile.h"
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif
#include <stdexcept>
#include <sstream>

namespace fuzzer {

TmpFile::TmpFile(const std::vector<uint8_t> & payload,
    const char * Template)
{
#ifdef WIN32
    char path[MAX_PATH+1];
    if (GetTempPathA(sizeof(path), path) == 0) {
        throw std::runtime_error("Failed to get temporary directory");
    }

    char filename[MAX_PATH+1];
    if (GetTempFileNameA(path, "fuz", 0, filename) == 0) {
        throw std::runtime_error("Failed to generate temporary name.");
    }

    _filename = filename;

    // now create the file
    FILE * file = fopen(_filename.c_str(), "w");
    if (!file) {
        throw std::runtime_error("Failed to open file for writing.");
    }

    if (fwrite(&payload[0],payload.size(), 1, file) != 1) {
        fclose(file);
        DeleteFileA(_filename.c_str());
        throw std::runtime_error("Failed to write file.");
    }
    fclose(file);
#else
#error "Support not implemented"
#endif
}

TmpFile::~TmpFile()
{
#ifdef WIN32
    if (!_filename.empty()) {
        DeleteFileA(_filename.c_str());
    }
#endif
}

}