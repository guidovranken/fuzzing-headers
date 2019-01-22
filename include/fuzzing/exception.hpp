#ifndef FUZZING_EXCEPTION_HPP
#define FUZZING_EXCEPTION_HPP

#include <exception>

namespace fuzzing {

class Exception : public std::exception {
    public:
        Exception() = default;
        /* typeid(T).name */
};

} /* namespace fuzzing */

#endif
