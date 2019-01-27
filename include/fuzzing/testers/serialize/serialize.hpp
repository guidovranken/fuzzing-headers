#ifndef FUZZING_TESTERS_SERIALIZE_SERIALIZE_HPP
#define FUZZING_TESTERS_SERIALIZE_SERIALIZE_HPP

#include <fuzzing/memory.hpp>
#include <functional>

namespace fuzzing {
namespace testers {
namespace serialize {

using fuzzing::memory::memory_test;

template <class ObjectType, class BinaryType>
class SerializeTester {
    using ObjectToBinaryFn = std::function<std::optional<BinaryType>(ObjectType)>;
    using BinaryToObjectFn = std::function<std::optional<ObjectType>(BinaryType)>;
    private:
        template <class InType, class OutType, typename In2OutFn, typename Out2InFn>
        std::optional<std::pair<OutType, OutType>> convert2X(const InType& input, In2OutFn in2OutFn, Out2InFn out2InFn) const {
            const auto outType1 = in2OutFn(input);

            if ( !outType1 ) {
                return {};
            }

            memory_test(*outType1);

            const auto inType1 = out2InFn(*outType1);

            if ( !inType1 ) {
                return {};
            }

            memory_test(*inType1);

            const auto outType2 = in2OutFn(*inType1);

            if ( !outType2 ) {
                return {};
            }

            return std::pair<OutType, OutType>(*outType1, *outType2);
        }

        template <class InType, class IntermediateType, typename In2IntermediateFn, typename Intermediate2InFn>
        std::optional<std::pair<InType, InType>> convert(const InType& input, In2IntermediateFn in2IntermediateFn, Intermediate2InFn intermediate2InFn) const {
            const auto intermediateType = in2IntermediateFn(input);
            if ( !intermediateType ) {
                return {};
            }

            memory_test(*intermediateType);

            const auto inType1 = intermediate2InFn(*intermediateType);

            if ( !inType1 ) {
                return {};
            }

            memory_test(*inType1);

            return std::pair<InType, InType>(input, *inType1);
        }

    protected:
        std::optional<std::pair<ObjectType, ObjectType>> binaryToObject2X(const BinaryType& input, BinaryToObjectFn binaryToObjectFn, ObjectToBinaryFn objectToBinaryFn) const {
            return convert2X<BinaryType, ObjectType>(input, binaryToObjectFn, objectToBinaryFn);
        }

        std::optional<std::pair<BinaryType, BinaryType>> objectToBinary2X(const ObjectType& input, ObjectToBinaryFn objectToBinaryFn, BinaryToObjectFn binaryToObjectFn) const {
            return convert2X<ObjectType, BinaryType>(input, objectToBinaryFn, binaryToObjectFn);
        }

        std::optional<std::pair<ObjectType, ObjectType>> objectToBinaryToObject(const ObjectType& input, ObjectToBinaryFn objectToBinaryFn, BinaryToObjectFn binaryToObjectFn) const {
            return convert<ObjectType, BinaryType>(input, objectToBinaryFn, binaryToObjectFn);
        }

        std::optional<std::pair<BinaryType, BinaryType>> binaryToObjectToBinary(const BinaryType& input, BinaryToObjectFn binaryToObjectFn, ObjectToBinaryFn objectToBinaryFn) const {
            return convert<BinaryType, ObjectType>(input, binaryToObjectFn, objectToBinaryFn);
        }

    public:
        SerializeTester(void) = default;
};

} /* namespace serialize */
} /* namespace testers */
} /* namespace fuzzing */

#endif
