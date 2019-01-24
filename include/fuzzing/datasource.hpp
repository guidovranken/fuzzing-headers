#ifndef FUZZING_DATASOURCE_HPP
#define FUZZING_DATASOURCE_HPP

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

class Datasource
{
    private:
        const uint8_t* data;
        const size_t size;
        size_t idx;
        size_t left;
        bool canAdvance(const size_t size);
    public:
        void copyAndAdvance(void* dest, const size_t size);
        Datasource(const uint8_t* _data, const size_t _size);

        template<class T> T Get(void);
        uint16_t GetChoice(void);
        std::vector<uint8_t> GetSomeData(const size_t max = 0);
        types::String<> GetString(void);
        types::Data<> GetData(void);
        template <class T> std::vector<T> GetVector(void);

        class OutOfData : public fuzzing::Exception {
            public:
                OutOfData() = default;
        };

        class DeserializationFailure : public fuzzing::Exception {
            public:
                DeserializationFailure() = default;
        };
};

Datasource::Datasource(const uint8_t* _data, const size_t _size) :
    data(_data), size(_size), idx(0), left(size)
{
}

bool Datasource::canAdvance(const size_t size)
{
    return size <= left;
}

void Datasource::copyAndAdvance(void* dest, const size_t size)
{
    if ( canAdvance(size) == false ) {
        throw OutOfData();
    }
    memcpy(dest, data + idx, size);
    idx += size;
    left -= size;
}

template<class T> T Datasource::Get(void)
{
    T ret;
    copyAndAdvance(&ret, sizeof(ret));
    return ret;
}

template <> bool Datasource::Get<bool>(void)
{
    uint8_t ret;
    copyAndAdvance(&ret, sizeof(ret));
    return (ret % 2) ? true : false;
}

template <> std::string Datasource::Get<std::string>(void)
{
    auto data = GetData();
    return std::string(data.data(), data.data() + data.size());
}

template <> std::vector<std::string> Datasource::Get<std::vector<std::string>>(void)
{
    std::vector<std::string> ret;
    while ( true ) {
        auto data = GetData();
        ret.push_back( std::string(data.data(), data.data() + data.size()) );
        if ( Get<bool>() == false ) {
            break;
        }
    }
    return ret;
}

uint16_t Datasource::GetChoice(void)
{
    return Get<uint16_t>();
}

std::vector<uint8_t> Datasource::GetSomeData(const size_t max)
{
    std::vector<uint8_t> ret;

    uint16_t size = Get<uint16_t>();

    if ( max > 0 && size > max ) {
        size = max;
    }

    if ( size == 0 || size > left ) {
        return ret;
    }
    
    ret.resize(size);
    copyAndAdvance(ret.data(), size);

    return ret;
}


types::String<> Datasource::GetString(void) {
    const auto data = GetSomeData();
    types::String<> ret(data.data(), data.size());
    return ret;
}

types::Data<> Datasource::GetData(void) {
    const auto data = GetSomeData();
    types::Data<> ret(data.data(), data.size());
    return ret;
}

template <class T>
std::vector<T> Datasource::GetVector(void) {
    std::vector<T> ret;

    while ( Get<bool>() == true ) {
        ret.push_back( Get<T>() );
    }

    return ret;
}

} /* namespace datasource */
} /* namespace fuzzing */

#endif
