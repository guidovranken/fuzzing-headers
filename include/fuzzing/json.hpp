#ifndef FUZZING_JSON_HPP
#define FUZZING_JSON_HPP

#include <fuzzing/datasource.hpp>
#include <fuzzing/test.hpp>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace fuzzing {

template <class ObjectType, class BinaryType, typename ObjectToBinaryFn, typename BinaryToObjectFn>
class SerializeTester {
    private:
        template <class InType, class OutType, typename In2OutFn, typename Out2InFn>
        std::optional<std::pair<OutType, OutType>> convert2X(const InType& input, In2OutFn in2OutFn, Out2InFn out2InFn) const {
            const auto outType1 = in2OutFn(input);

            if ( !outType1 ) {
                return {};
            }

            const auto inType1 = out2InFn(*outType1);

            if ( !inType1 ) {
                return {};
            }

            const auto outType2 = in2OutFn(*inType1);

            if ( !outType2 ) {
                return {};
            }

            return std::pair<OutType, OutType>(*outType1, *outType2);
        }

    protected:
        std::optional<std::pair<ObjectType, ObjectType>> binaryToObject2X(const BinaryType& input, BinaryToObjectFn binaryToObjectFn, ObjectToBinaryFn objectToBinaryFn) const {
            return convert2X<BinaryType, ObjectType>(input, binaryToObjectFn, objectToBinaryFn);
        }

        std::optional<std::pair<BinaryType, BinaryType>> objectToBinary2X(const ObjectType& input, ObjectToBinaryFn objectToBinaryFn, BinaryToObjectFn binaryToObjectFn) const {
            return convert2X<ObjectType, BinaryType>(input, objectToBinaryFn, binaryToObjectFn);
        }

    public:
        SerializeTester(void) = default;
};

template <class ObjectType, typename ObjectToBinaryFn, typename BinaryToObjectFn>
class JsonTester : public SerializeTester<ObjectType, std::string, ObjectToBinaryFn, BinaryToObjectFn> {
    private:
        const ObjectToBinaryFn& objectToBinaryFn;
        const BinaryToObjectFn& binaryToObjectFn;
        std::unique_ptr<Multitest> mt;

        template <class InType, typename Convert2XFn>
        bool testConversion(const InType& input, Convert2XFn convert2XFn) const {
            const auto res = convert2XFn(input);

            if ( !res ) {
                return true;
            }

            if ( res->first != res->second ) {
                return false;
            }

            return true;
        }

        bool testStringConversion(const std::string& input) const {
            const auto binaryToObject2XWrapper = [this](const std::string& input) -> std::optional<std::pair<ObjectType, ObjectType>> {
                return this->binaryToObject2X(input, binaryToObjectFn, objectToBinaryFn);
            };

            return testConversion<std::string, decltype(binaryToObject2XWrapper)>(input, binaryToObject2XWrapper);
        }

        bool testObjectConversion(const ObjectType& input) const {
            const auto ObjectToBinary2XWrapper = [this](const std::string& input) -> std::optional<std::pair<ObjectType, ObjectType>> {
                return this->objectToBinary2X(input, objectToBinaryFn, binaryToObjectFn);
            };

            return testConversion<ObjectType, decltype(ObjectToBinary2XWrapper)>(input, ObjectToBinary2XWrapper);
        }

        /* Start tests */
        void test_StringConversion(Datasource& ds) {
            const auto input = ds.Get<std::string>();
            testStringConversion(input);
        }

    public:
        JsonTester(ObjectToBinaryFn& objectToBinaryFn, BinaryToObjectFn& binaryToObjectFn) :
            SerializeTester<ObjectType, std::string, ObjectToBinaryFn, BinaryToObjectFn>(), 
            objectToBinaryFn(objectToBinaryFn), binaryToObjectFn(binaryToObjectFn),
            mt(
                new Multitest(
                    {
                      SingleTest(std::bind(&JsonTester::test_StringConversion, this, std::placeholders::_1)),
                    }
                )
            )
            {}

        bool Test(Datasource& ds) {
            mt->Test(ds);
            return true;
        }
};

} /* namespace fuzzing */

#endif
