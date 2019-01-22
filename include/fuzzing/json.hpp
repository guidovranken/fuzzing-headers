#ifndef FUZZING_JSON_HPP
#define FUZZING_JSON_HPP

#include <fuzzing/datasource.hpp>
#include <fuzzing/test.hpp>
#include <fuzzing/truth.hpp>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace fuzzing {

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

template <class ObjectType>
class JsonManipulator {
    public:
        JsonManipulator(void) = default;
        virtual ~JsonManipulator() = default;

        /* Conversion */
        virtual std::optional<ObjectType> StringToObject(const std::string& input) {
            (void)input;

            return {};
        }

        virtual std::optional<std::string> ObjectToString(const ObjectType& input) {
            (void)input;

            return {};
        }

        /* Comparison */
        virtual std::optional<bool> IsEqual(const ObjectType& input1, const ObjectType& input2) {
            (void)input1;
            (void)input2;

            return {};
        }

        virtual std::optional<bool> IsGreaterThan(const ObjectType& input1, const ObjectType& input2) {
            (void)input1;
            (void)input2;

            return {};
        }

        virtual std::optional<bool> IsLessThan(const ObjectType& input1, const ObjectType& input2) {
            (void)input1;
            (void)input2;

            return {};
        }

        virtual std::optional<bool> IsEqualOrGreaterThan(const ObjectType& input1, const ObjectType& input2) {
            (void)input1;
            (void)input2;

            return {};
        }

        virtual std::optional<bool> IsEqualOrLessThan(const ObjectType& input1, const ObjectType& input2) {
            (void)input1;
            (void)input2;

            return {};
        }

        /* */
        virtual std::optional<bool> IsMember(const ObjectType& input, const std::string& memberName) {
            (void)input;
            (void)memberName;

            return {};
        }

        virtual std::optional<bool> HasIndex(const ObjectType& input, const uint64_t index) {
            (void)input;
            (void)index;

            return {};
        }

        /* Altering objects */
        virtual bool RemoveMember(ObjectType& input, const std::string& memberName) {
            (void)input;
            (void)memberName;

            return false;
        }

        virtual bool RemoveIndex(ObjectType& input, const uint64_t index) {
            (void)input;
            (void)index;

            return false;
        }

        virtual bool Swap(ObjectType& input1, ObjectType& input2) {
            (void)input1;
            (void)input2;

            return false;
        }

        virtual bool Clear(ObjectType& input) {
            (void)input;

            return false;
        }

        virtual bool Set(ObjectType& input1, const ObjectType& input2) {
            (void)input1;
            (void)input2;

            return false;
        }

        /* Type determination */
        virtual std::optional<bool> IsObject(const ObjectType& input) {
            (void)input;

            return {};
        }

        virtual std::optional<bool> IsArray(const ObjectType& input) {
            (void)input;

            return {};
        }

        virtual std::optional<bool> IsString(const ObjectType& input) {
            (void)input;

            return {};
        }

        virtual std::optional<bool> IsNumber(const ObjectType& input) {
            (void)input;

            return {};
        }

        virtual std::optional<bool> IsBoolean(const ObjectType& input) {
            (void)input;

            return {};
        }

        /* Tree introspection */
        virtual std::optional<std::vector<std::string>> GetMemberNames(const ObjectType& input) {
            (void)input;

            return {};
        }

        virtual std::optional<uint64_t> GetArraySize(const ObjectType& input) {
            (void)input;

            return {};
        }

        /* Creation */
        virtual std::optional<ObjectType> Copy(const ObjectType& input) {
            (void)input;
            return {};
        }

        virtual bool SetString(ObjectType& input, const std::string string) {
            (void)input;
            (void)string;

            return false;
        }

        /* Traversal */
#if 0
        virtual std::optional<ObjectType&> GetReference(const ObjectType& input, const std::string& memberName) {
            (void)input;
            (void)memberName;

            return {};
        }

        virtual std::optional<ObjectType&> GetReference(const ObjectType& input, const uint64_t index) {
            (void)input;
            (void)index;

            return {};
        }
#endif
 
};

template <class ObjectType>
class JsonTester : public SerializeTester<ObjectType, std::string> {
    private:
        const std::unique_ptr<JsonManipulator<ObjectType>> jsonManipulator;
        const std::unique_ptr<Multitest> mt;
        std::optional<ObjectType> slots[2] = {};

        template <class InType, typename Convert2XFn>
        void testConversion(const InType& input, Convert2XFn convert2XFn) const {
            const auto res = convert2XFn(input);

            if ( !res ) {
                return;
            }

            if ( res->first != res->second ) {
                /* TODO throw */
                abort();
                return;
            }
        }

        void testStringConversion(const std::string& input) const {
            const auto binaryToObject2XWrapper = [this](const std::string& input) -> std::optional<std::pair<ObjectType, ObjectType>> {
                return this->binaryToObject2X(
                        input,
                        std::bind(&JsonManipulator<ObjectType>::StringToObject, jsonManipulator.get(), std::placeholders::_1),
                        std::bind(&JsonManipulator<ObjectType>::ObjectToString, jsonManipulator.get(), std::placeholders::_1));
            };

            return testConversion<std::string, decltype(binaryToObject2XWrapper)>(input, binaryToObject2XWrapper);
        }

        void testObjectConversion(const ObjectType& input) const {
            const auto ObjectToBinary2XWrapper = [this](const std::string& input) -> std::optional<std::pair<ObjectType, ObjectType>> {
                return this->objectToBinary2X(
                        input,
                        std::bind(&JsonManipulator<ObjectType>::ObjectToString, jsonManipulator.get(), std::placeholders::_1),
                        std::bind(&JsonManipulator<ObjectType>::StringToObject, jsonManipulator.get(), std::placeholders::_1));
            };

            return testConversion<ObjectType, decltype(ObjectToBinary2XWrapper)>(input, ObjectToBinary2XWrapper);
        }

        std::optional<ObjectType> getObject(Datasource& ds) {
            const auto choice = ds.GetChoice() % 1;
            switch ( choice ) {
                case    0:
                    {
                        const auto input = ds.Get<std::string>();
                        return jsonManipulator->StringToObject(input);
                    }
                    break;
            }
            abort();
        }

        /* Start tests */
        void test_StringConversion(Datasource& ds) {
            const auto input = ds.Get<std::string>();
            testStringConversion(input);
        }

        void test_Comparison(Datasource& ds) {
            const auto input1 = getObject(ds);
            if ( !input1 ) {
                return;
            }

            const auto input2 = getObject(ds);
            if ( !input2 ) {
                return;
            }

            const auto EQ = jsonManipulator->IsEqual(*input1, *input2);
            const auto GT = jsonManipulator->IsGreaterThan(*input1, *input2);
            const auto LT = jsonManipulator->IsLessThan(*input1, *input2);
            const auto EQGT = jsonManipulator->IsEqualOrGreaterThan(*input1, *input2);
            const auto EQLT = jsonManipulator->IsEqualOrLessThan(*input1, *input2);

            if ( fuzzing::truth::isValid( {EQ, GT, LT, EQGT, EQLT} ) == false ) {
                /* TODO throw */
                abort();
            }
        }

        void test_Clear(Datasource& ds) {
            auto input = getObject(ds);

            if ( !input ) {
                return;
            }

            jsonManipulator->Clear(*input);
        }

        void test_Copy(Datasource& ds) {
            auto input = getObject(ds);

            if ( !input ) {
                return;
            }

            const auto res = jsonManipulator->Copy(*input);
            if ( !res ) {
                return;
            }

            if ( *input != res ) {
                /* TODO throw */
                abort();
            }

            const auto isEQ = jsonManipulator->IsEqual(*input, *res);
            if ( isEQ ) {
                if ( !(*isEQ) ) {
                    /* TODO throw */
                    abort();
                }
            }
        }

    public:
        JsonTester(std::unique_ptr<JsonManipulator<ObjectType>> jsonManipulator) :
            SerializeTester<ObjectType, std::string>(),
            jsonManipulator(std::move(jsonManipulator)),
            mt(
                new Multitest(
                    {
                      SingleTest(std::bind(&JsonTester::test_StringConversion, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_Comparison, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_Clear, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_Copy, this, std::placeholders::_1)),
                    }
                )
            )
            {}

        void Test(Datasource& ds) {
            mt->Test(ds);
        }
};

} /* namespace fuzzing */

#endif
