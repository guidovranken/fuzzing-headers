#ifndef FUZZING_DATASOURCE_DATASOURCE_HPP
#define FUZZING_DATASOURCE_DATASOURCE_HPP

#include <fuzzing/exception.hpp>
#include <fuzzing/types.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace fuzzing {
namespace datasource  {

class Base
{
    protected:
        virtual bool canAdvance(const size_t size) = 0;
    public:
        virtual void copyAndAdvance(void* dest, const size_t size, const uint64_t id = 0) = 0;
        Base(void) = default;
        virtual ~Base(void) = default;

        template<class T> T Get(const uint64_t id = 0);
        uint16_t GetChoice(const uint64_t id = 0);
        std::vector<uint8_t> GetSomeData(const uint64_t id, const size_t max = 0);
        types::String<> GetString(const uint64_t id = 0);
        types::Data<> GetData(const uint64_t id = 0);
        template <class T> std::vector<T> GetVector(const uint64_t id = 0);

        class OutOfData : public fuzzing::exception::FlowException {
            public:
                OutOfData() = default;
        };

        class DeserializationFailure : public fuzzing::exception::FlowException {
            public:
                DeserializationFailure() = default;
        };
};

template<class T> T Base::Get(const uint64_t id)
{
    T ret;
    copyAndAdvance(&ret, sizeof(ret), id);
    return ret;
}

template <> bool Base::Get<bool>(const uint64_t id)
{
    uint8_t ret;
    copyAndAdvance(&ret, sizeof(ret), id);
    return (ret % 2) ? true : false;
}

template <> std::string Base::Get<std::string>(const uint64_t id)
{
    auto data = GetData(id);
    return std::string(data.data(), data.data() + data.size());
}

template <> std::vector<std::string> Base::Get<std::vector<std::string>>(const uint64_t id)
{
    std::vector<std::string> ret;
    while ( true ) {
        auto data = GetData(id);
        ret.push_back( std::string(data.data(), data.data() + data.size()) );
        if ( Get<bool>(id) == false ) {
            break;
        }
    }
    return ret;
}

uint16_t Base::GetChoice(const uint64_t id)
{
    return Get<uint16_t>(id);
}

std::vector<uint8_t> Base::GetSomeData(const uint64_t id, const size_t max)
{
    std::vector<uint8_t> ret;

    uint16_t size = Get<uint16_t>(id);

    if ( max > 0 && size > max ) {
        size = max;
    }

    if ( size == 0 || canAdvance(size) == false ) {
        return ret;
    }
    
    ret.resize(size);
    copyAndAdvance(ret.data(), size, id);

    return ret;
}


types::String<> Base::GetString(const uint64_t id) {
    const auto data = GetSomeData(id);
    types::String<> ret(data.data(), data.size());
    return ret;
}

types::Data<> Base::GetData(const uint64_t id) {
    const auto data = GetSomeData(id);
    types::Data<> ret(data.data(), data.size());
    return ret;
}

template <class T>
std::vector<T> Base::GetVector(const uint64_t id) {
    std::vector<T> ret;

    while ( Get<bool>(id) == true ) {
        ret.push_back( Get<T>(id) );
    }

    return ret;
}

class Datasource : public Base
{
    private:
        const uint8_t* data;
        const size_t size;
        size_t idx;
        size_t left;
        bool canAdvance(const size_t size) override;
    public:
        void copyAndAdvance(void* dest, const size_t size, const uint64_t id = 0) override;
        Datasource(const uint8_t* _data, const size_t _size);
};

Datasource::Datasource(const uint8_t* _data, const size_t _size) :
    Base(), data(_data), size(_size), idx(0), left(size)
{
}

bool Datasource::canAdvance(const size_t size)
{
    return size <= left;
}

void Datasource::copyAndAdvance(void* dest, const size_t size, const uint64_t id)
{
    (void)id;

    if ( canAdvance(size) == false ) {
        throw OutOfData();
    }
    memcpy(dest, data + idx, size);
    idx += size;
    left -= size;
}

} /* namespace datasource */
} /* namespace fuzzing */

#endif
