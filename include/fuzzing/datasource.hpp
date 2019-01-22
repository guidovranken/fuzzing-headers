#ifndef FUZZING_DATASOURCE_HPP
#define FUZZING_DATASOURCE_HPP

#include <fuzzing/exception.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace fuzzing {

class String {
    private:
        char* s = nullptr;
        size_t _size;
    public:
        String(const uint8_t* data, size_t size) {
            s = static_cast<char*>(malloc(size+1));
            if ( size > 0 ) {
                memcpy(s, data, size);
            }
            s[size] = 0;
            _size = size;
        }
        ~String() {
            free(s);
        }
        char* data(void) {
            return s;
        }
        size_t size(void) const {
            return _size;
        }
};

class Data {
    private:
        char* s = nullptr;
        size_t _size;
    public:
        Data(const uint8_t* data, size_t size) {
            if ( size > 0 ) {
                s = static_cast<char*>(malloc(size));
                memcpy(s, data, size);
            } else {
                s = (char*)0x12;
            }
            _size = size;
        }
        ~Data() {
            if ( _size > 0 ) {
                free(s);
            }
        }
        char* data(void) {
            return s;
        }
        size_t size(void) const {
            return _size;
        }
};

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
        uint8_t GetUint8(void);
        uint16_t GetUint16(void);
        uint32_t GetUint32(void);
        uint64_t GetUint64(void);
        std::vector<uint8_t> GetSomeData(const size_t max = 0);
        String GetString(void);
        Data GetData(void);
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

uint8_t Datasource::GetUint8(void)
{
    uint8_t ret = 0;
    copyAndAdvance(&ret, sizeof(ret));
    return ret;
}

uint16_t Datasource::GetUint16(void)
{
    uint16_t ret = 0;
    copyAndAdvance(&ret, sizeof(ret));
    return ret;
}

uint32_t Datasource::GetUint32(void)
{
    uint16_t ret = 0;
    copyAndAdvance(&ret, sizeof(ret));
    return ret;
}

uint64_t Datasource::GetUint64(void)
{
    uint16_t ret = 0;
    copyAndAdvance(&ret, sizeof(ret));
    return ret;
}

std::vector<uint8_t> Datasource::GetSomeData(const size_t max)
{
    std::vector<uint8_t> ret;

    uint16_t size = GetUint16();

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


String Datasource::GetString(void) {
    const auto data = GetSomeData();
    String ret(data.data(), data.size());
    return ret;
}

Data Datasource::GetData(void) {
    const auto data = GetSomeData();
    Data ret(data.data(), data.size());
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

} /* namespace fuzzing */

#endif
