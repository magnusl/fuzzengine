#include "filemutator.h"
#include <cstdio>
#include <sstream>

namespace fuzzer {

namespace runtime {

FileMutator::FileMutator(const char * filename) :
    _name(filename),
    _phase(BIT_INVERSE),
    _offset(0)
{
    FILE * file = fopen(filename, "rb");
    if (!file) {
        throw std::runtime_error("Failed to open file for reading.");
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);

    if (!size) {
        fclose(file);
        throw std::runtime_error("Empty file.");
    }

    _data.resize(size);
    if (fread(&_data[0], size, 1, file) != 1) {
        fclose(file);
        throw std::runtime_error("Failed to read file contents.");
    }

    fclose(file);
}

FileMutator::~FileMutator()
{
}

bool FileMutator::finished()
{
    return _phase == DONE;
}

void FileMutator::reset()
{
    _phase  = BIT_INVERSE;
    _offset = 0;
}

bool FileMutator::mutate()
{
    if (finished()) {
        return false;
    }
    switch(_phase) {
    case BIT_INVERSE:
        if ((++_offset) == _data.size()) {
            _phase = BYTE_REMOVAL;
        }
        break;
    case BYTE_REMOVAL:
        if ((++_offset) == _data.size()) {
            _phase = DONE;
            return false;
        }
        break;
    case DONE:
        return false;
    }
    return true;
}

void FileMutator::evaluate(Buffer & buffer)
{
    switch(_phase) {
    case BIT_INVERSE:
        {
            if (_offset > 0) { //< write unmodified data before
                buffer.write(&_data[0], _offset);
            }
            uint8_t fuzzed = ~_data[_offset];
            buffer.write(&fuzzed, sizeof(fuzzed));
            if ((_offset + 1) < _data.size()) { //< write unmodified data after
                buffer.write(&_data[_offset + 1], _data.size() - _offset - 1);
            }
            break;
        }
    case BYTE_REMOVAL:
        {
            if (_offset > 0) { //< write unmodified data before
                buffer.write(&_data[0], _offset);
            }
            // ignore byte, write data after
            if ((_offset + 1) < _data.size()) { //< write unmodified data after
                buffer.write(&_data[_offset + 1], _data.size() - _offset - 1);
            }
            break;
        }
    default:
        break;
    }
}

bool FileMutator::state(std::string & state)
{
    std::stringstream ss;
    
    ss << "file: \"" << _name << "\",";
    switch(_phase) {
    case BIT_INVERSE:       ss << "bitinverse, offset=" << _offset; break;
    case BYTE_REMOVAL:      ss << "byteremoval, offset=" << _offset; break;
    case DONE:              ss << "done"; break;
    }
    state = ss.str();
    return true;
}

} // namespace runtime

} // namespace fuzzer
