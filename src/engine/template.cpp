#include "template.h"
#include "buffer.h"
#include "integermutator.h"
#include "lazytemplate.h"
#include <vector>
#include <map>

using namespace std;

namespace fuzzer {

namespace runtime {

using namespace fuzzer::parser;

///
/// \class  Item
/// \brief  Template item
///
struct Item {
    enum {
        BYTE,
        WORD,
        DWORD,
        QWORD,
        FLOAT,
        DOUBLE,
        BUFFER,
        LAZY
    } type;

    union {
        uint8_t             byte;
        uint16_t            word;
        uint32_t            dword;
        uint64_t            qword;
        float               spf;
        double              dpf;
        LazyEvaluation *    lazy;
        struct {
            size_t  count;
            void *  data;
        } buffer;
    } u;
};

void reset(Item & item)
{
    if (item.type == Item::BUFFER) {
        delete item.u.buffer.data;
        item.u.buffer.data;
        item.u.buffer.count = 0;
    }
}

///
/// \class  Template::Implementation
///
class Template::Implementation {
public:
    vector<Item>    _items;
    bool            _big_endian;
};

Template::Template()
{
    _impl = new Template::Implementation();
    _impl->_big_endian = true;
}

Template::~Template()
{
    for(size_t i = 0, count = _impl->_items.size(); i < count; ++i) {
        reset(_impl->_items[i]);
    }
    delete _impl;
}

Template & Template::big_endian()
{
    _impl->_big_endian = true;
    return *this;
}

Template & Template::little_endian()
{
    _impl->_big_endian = false;
    return *this;
}
size_t Template::u8(uint8_t byte, size_t pos)
{
    if (pos == ~0L) { // add new item
        Item item;
        item.type   = Item::BYTE;
        item.u.byte = byte;
        _impl->_items.push_back(item);
        return _impl->_items.size() - 1;
    } else { // replace current item
        if (pos >= _impl->_items.size()) {
            throw std::runtime_error("Invalid position specified.");
        }
        reset(_impl->_items[pos]);
        _impl->_items[pos].type     = Item::BYTE;
        _impl->_items[pos].u.byte   = byte;
        return pos;
    }
}

size_t Template::u16(uint16_t word, size_t pos)
{
    if (pos == ~0L) { // add new item
        Item item;
        item.type   = Item::WORD;
        item.u.word = word;
        _impl->_items.push_back(item);
        return _impl->_items.size() - 1;
    } else { // replace current item
        if (pos >= _impl->_items.size()) {
            throw std::runtime_error("Invalid position specified.");
        }
        reset(_impl->_items[pos]);
        _impl->_items[pos].type     = Item::WORD;
        _impl->_items[pos].u.word   = word;
        return pos;
    }
}

size_t Template::u32(uint32_t dword, size_t pos)
{
    if (pos == ~0L) { // add new item
        Item item;
        item.type       = Item::DWORD;
        item.u.dword    = dword;
        _impl->_items.push_back(item);
        return _impl->_items.size() - 1;
    } else { // replace current item
        if (pos >= _impl->_items.size()) {
            throw std::runtime_error("Invalid position specified.");
        }
        reset(_impl->_items[pos]);
        _impl->_items[pos].type     = Item::DWORD;
        _impl->_items[pos].u.dword  = dword;
        return pos;
    }
}

size_t Template::u64(uint64_t qword, size_t pos)
{
    if (pos == ~0L) { // add new item
        Item item;
        item.type       = Item::QWORD;
        item.u.qword    = qword;
        _impl->_items.push_back(item);
        return _impl->_items.size() - 1;
    } else { // replace current item
        if (pos >= _impl->_items.size()) {
            throw std::runtime_error("Invalid position specified.");
        }
        reset(_impl->_items[pos]);
        _impl->_items[pos].type     = Item::QWORD;
        _impl->_items[pos].u.qword  = qword;
        return pos;
    }
}

size_t Template::_array(const void * data, size_t size, size_t pos)
{
    if (pos == ~0L) { // add new item
        Item item;
        item.type           = Item::BUFFER;
        item.u.buffer.count = size;
        item.u.buffer.data  = new (std::nothrow) uint8_t[size];
        memcpy(item.u.buffer.data, data, size);
        _impl->_items.push_back(item);
        return _impl->_items.size() - 1;
    } else { // replace current item
        if (pos >= _impl->_items.size()) {
            throw std::runtime_error("Invalid position specified.");
        }
        reset(_impl->_items[pos]);
        Item item;
        item.type           = Item::BUFFER;
        item.u.buffer.count = size;
        item.u.buffer.data  = new (std::nothrow) uint8_t[size];
        memcpy(item.u.buffer.data, data, size);
        _impl->_items.push_back(item);
        return pos;
    }
}

size_t Template::lazy(LazyEvaluation * evaluator, size_t pos)
{
    if (pos == ~0L) { // add new item
        Item item;
        item.type           = Item::LAZY;
        item.u.lazy         = evaluator;
        _impl->_items.push_back(item);
        return _impl->_items.size() - 1;
    } else { // replace current item
        if (pos >= _impl->_items.size()) {
            throw std::runtime_error("Invalid position specified.");
        }
        reset(_impl->_items[pos]);
        Item item;
        item.type           = Item::LAZY;
        item.u.lazy         = evaluator;
        _impl->_items.push_back(item);
        return _impl->_items.size() - 1;
    }
}

std::vector<Mutator *> Template::GetMutators() const
{
    std::vector<Mutator *> mutators;
    for(size_t i = 0; i < _impl->_items.size(); ++i) {
        if (_impl->_items[i].type == Item::LAZY) {
            if (Mutator * mutator = dynamic_cast<Mutator *>(_impl->_items[i].u.lazy)) {
                mutators.push_back(mutator);
            }
        }
    }
    return mutators;
}

void Template::generate(std::vector<uint8_t> & data)
{
    fuzzer::runtime::Buffer dst(data);
    return generate(dst);
}

void Template::generate(Buffer & dst)
{
    for(size_t i = 0, count = _impl->_items.size(); i < count; ++i) {
        const Item & item = _impl->_items[i];
        switch(item.type) {
        case Item::BYTE:    dst.writeU8(item.u.byte); break;
        case Item::WORD:    dst.writeU16(item.u.word); break;
        case Item::DWORD:   dst.writeU32(item.u.dword); break;
        case Item::BUFFER:  dst.write(item.u.buffer.data, item.u.buffer.count); break;
        case Item::LAZY:    if (item.u.lazy) item.u.lazy->evaluate(dst); break;
        default:
            break;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
//                      Create template from syntax tree                     //
///////////////////////////////////////////////////////////////////////////////

size_t UpdateWithConstant(shared_ptr<Template> tp,
    const shared_ptr<Constant> & constant,
    std::map<size_t, Mutator *> & mutators)
{
    if (constant->_fuzzy) {
        Mutator * mutator = nullptr;
        switch(constant->_type) {
        case parser::UNSIGNED8:     mutator = new UnsignedMutator<uint8_t>(constant->u.u8); break;
        case parser::UNSIGNED16:    mutator = new UnsignedMutator<uint16_t>(constant->u.u16); break;
        case parser::UNSIGNED32:    mutator = new UnsignedMutator<uint32_t>(constant->u.u32); break;
        case parser::UNSIGNED64:    mutator = new UnsignedMutator<uint64_t>(constant->u.u64); break;
        default:
            throw std::runtime_error("Mutator not available for constan type.");
        }
        mutators[constant->_id] = mutator;
        return tp->lazy(mutator);
    } else {
        switch(constant->_type) {
        case parser::UNSIGNED8:     return tp->u8(constant->u.u8);
        case parser::UNSIGNED16:    return tp->u16(constant->u.u16);
        case parser::UNSIGNED32:    return tp->u32(constant->u.u32);
        case parser::UNSIGNED64:    return tp->u64(constant->u.u64);
        default:
            throw std::runtime_error("Constant type not supported.");
        }
    }
}

void UpdateTemplateWithExpression(shared_ptr<Template> tp, shared_ptr<Expression> exp,
    map<size_t, Mutator *> & mutators,
    map<string, shared_ptr<Template> > & declarations)
{
    switch(exp->GetType()) 
    {
    case Expression::EXP_CONSTANT:
        /// constant expression
        if (shared_ptr<Constant> constant = dynamic_pointer_cast<Constant>(exp)) {
            UpdateWithConstant(tp, constant, mutators);
        } else {
            throw runtime_error("Failed to cast to 'Constant'");
        }
        break;
    case Expression::EXP_REFERENCE:
        /// reference to a declaration
        if (shared_ptr<Reference> ref = dynamic_pointer_cast<Reference>(exp)) {
            auto it = declarations.find(ref->_name);
            if (it == declarations.end()) {
                throw runtime_error("Unknown variable referenced.");
            }
            tp->lazy(new LazyTemplateData(it->second));
        } else {
            throw runtime_error("Failed to cast to 'Reference'");
        }
        break;
    default:
        throw runtime_error("Expression type not supported.");
    }
}

///
/// \brief  Updates a template from a output statement
///
void UpdateTemplateFromOutput(
    shared_ptr<Template> tp,
    const fuzzer::parser::Output & output,
    std::map<size_t, Mutator *> & mutators,
    map<string, shared_ptr<Template> > & declarations)
{
    for(auto it = output._expressions.begin(); it != output._expressions.end(); it++) {
        UpdateTemplateWithExpression(tp, *it, mutators, declarations);
    }
}

///
/// \brief      Creates a template from a declaration
/// \details    A declaration of the form $x = expression is converted into a template.
///
shared_ptr<Template> CreateTemplateFromDeclaration(const fuzzer::parser::Declaration & declaration,
    map<size_t, Mutator *> & mutators,
    map<string, shared_ptr<Template> > & declarations)
{
    shared_ptr<Template> tp = make_shared<Template>();
    UpdateTemplateWithExpression(tp, declaration._value, mutators, declarations);
    return tp;
}

} // namespace runtime

} // namespace fuzzer
