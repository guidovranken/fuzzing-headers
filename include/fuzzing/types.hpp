#ifndef FUZZING_TYPES_HPP
#define FUZZING_TYPES_HPP

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fuzzing/memory.hpp>
#include <vector>
#include <string>

namespace fuzzing {
namespace types {

template <bool UseMSAN = false>
class Container {
    private:
        uint8_t* InvalidAddress = (uint8_t*)0x12;

        void copy(const uint8_t* data, size_t size) {
            if ( size > 0 ) {
                std::memcpy(_data, data, size);
            }
        }

    protected:
        uint8_t* _data = InvalidAddress;
        size_t _size = 0;

        void allocate(size_t size) {
            if ( size > 0 ) {
                _data = static_cast<uint8_t*>(malloc(size));
            } else {
                _data = InvalidAddress;
            }
        };

        void allocate_and_copy(const uint8_t* data, size_t size) {
            allocate(size);
            copy(data, size);
        }

        void allocate_plus_1_and_copy(const uint8_t* data, size_t size) {
            allocate(size+1);
            copy(data, size);
        }

        void access_hook(void) const {
            if ( UseMSAN == true ) {
                memory::memory_test_msan(_data, _size);
            } 
        }

        void free(void) {
            access_hook();

            if ( _size > 0 ) {
                std::free(_data);
                _data = InvalidAddress;
                _size = 0;
            }
        }

    public:
        uint8_t* data(void) {
            access_hook();
            return _data;
        }

        size_t size(void) const {
            access_hook();
            return _size;
        }

        Container(void) = default;

        virtual ~Container(void) {
            this->free();
        }

    
};

template <bool UseMSAN = false>
class String : public Container<UseMSAN> {
    using Container<UseMSAN>::_data;
    using Container<UseMSAN>::_size;
    using Container<UseMSAN>::allocate_plus_1_and_copy;
    public:
        String(const uint8_t* data, size_t size) : Container<UseMSAN>() {
            _size = size + 1;
            allocate_plus_1_and_copy(data, size);
            _data[_size] = 0;
        }

        String(std::vector<uint8_t> v) : Container<UseMSAN>() {
            _size = v.size() + 1;
            allocate_plus_1_and_copy(v.data(), v.size());
            _data[_size] = 0;
        }

        String(std::string s) : Container<UseMSAN>() {
            _size = s.size() + 1;
            allocate_plus_1_and_copy(s.data(), s.size());
            _data[_size] = 0;
        }

        ~String() = default;

        char* c_str(void) {
            return static_cast<char*>(_data);
        }
};

template <bool UseMSAN = false>
class Data : public Container<UseMSAN> {
    using Container<UseMSAN>::_data;
    using Container<UseMSAN>::_size;
    using Container<UseMSAN>::allocate_and_copy;
    public:
        Data(const uint8_t* data, size_t size) : Container<UseMSAN>() {
            _size = size;
            allocate_and_copy(data, _size);
        }

        ~Data() = default;
};

} /* namespace types */
} /* namespace fuzzing */

#endif

