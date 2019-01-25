#ifndef FUZZING_JSON_HPP
#define FUZZING_JSON_HPP

#include <fuzzing/datasource.hpp>
#include <fuzzing/exception.hpp>
#include <fuzzing/memory.hpp>
#include <fuzzing/test.hpp>
#include <fuzzing/truth.hpp>
#include <cmath>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <set>

#include <unistd.h>

namespace fuzzing {

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

            return nullptr;
        }

        virtual std::optional<std::string> ObjectToString(const ObjectType& input) {
            (void)input;

            return {};
        }

        /* Introspection */
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

        virtual std::optional<std::vector<std::string>> GetMemberNames(const ObjectType& input) {
            (void)input;

            return {};
        }

        virtual std::optional<uint64_t> GetArraySize(const ObjectType& input) {
            (void)input;

            return {};
        }

        virtual std::optional<double> GetDouble(ObjectType& input) {
            (void)input;

            return {};
        }

        virtual std::optional<int32_t> GetInt32(ObjectType& input) {
            (void)input;

            return {};
        }

        virtual std::optional<int64_t> GetInt64(ObjectType& input) {
            (void)input;

            return {};
        }

        virtual std::optional<bool> HasMember(const ObjectType& input, const std::string name) {
            (void)input;
            (void)name;

            return {};
        }

        virtual ObjectType& GetMemberReference(ObjectType& input, const std::string name) {
            (void)name;
            /* TODO abort? */
            return input;
        }

        virtual ObjectType& GetMemberReference(ObjectType& input, const uint64_t index) {
            (void)index;
            /* TODO abort? */
            return input;
        }


        /* CRUD */
        virtual std::optional<ObjectType> Copy(const ObjectType& input) {
            (void)input;

            return {};
        }

        virtual bool SetKey(ObjectType& dest, const std::string key) {
            (void)dest;
            (void)key;

            return false;
        }

        virtual bool SetDouble(ObjectType& dest, const double val) {
            (void)dest;
            (void)val;

            return false;
        }

        virtual bool SetInt32(ObjectType& dest, const int32_t val) {
            (void)dest;
            (void)val;

            return false;
        }

        virtual bool SetInt64(ObjectType& dest, const int64_t val) {
            (void)dest;
            (void)val;

            return false;
        }

        virtual bool SetString(ObjectType& input, const std::string string) {
            (void)input;
            (void)string;

            return false;
        }

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
};

template <class ObjectType>
class JsonTester : public SerializeTester<ObjectType, std::string> {
    public:
        using global_TargetException = exception::TargetException;
        class TargetException : public global_TargetException {
            public:
                TargetException(const std::string reason) : global_TargetException(reason) { }
        };

    private:
        ObjectType slots[2];
        const std::unique_ptr<Multitest> mt;
        const std::unique_ptr<JsonManipulator<ObjectType>> jsonManipulator;

        template <class InType, typename Convert2XFn>
        void testConversion(const InType& input, Convert2XFn convert2XFn) const {
            const auto res = convert2XFn(input);

            if ( !res ) {
                return;
            }

            if ( res->first != res->second ) {
                throw TargetException("Double conversion mismatch");
            }
        }

        std::optional<std::string> objectToStringCStr(const ObjectType& input) {
            const auto res = jsonManipulator->ObjectToString(input);
            if ( !res ) {
                return {};
            }

            return std::string(res->data(), res->data() + strlen(res->c_str()));
        }

        void testStringConversion(const std::string& input) const {
            const auto binaryToObject2XWrapper = [this](const std::string& input) -> std::optional<std::pair<ObjectType, ObjectType>> {
                return this->binaryToObject2X(
                        input,
                        std::bind(&JsonManipulator<ObjectType>::StringToObject, jsonManipulator.get(), std::placeholders::_1),
                        std::bind(&JsonManipulator<ObjectType>::ObjectToString, jsonManipulator.get(), std::placeholders::_1));
            };

            testConversion<std::string, decltype(binaryToObject2XWrapper)>(input, binaryToObject2XWrapper);
        }

        void testStringConversionCStr(const std::string& input) {
            const auto binaryToObject2XWrapper = [this](const std::string& input) -> std::optional<std::pair<ObjectType, ObjectType>> {
                return this->binaryToObject2X(
                        input,
                        std::bind(&JsonManipulator<ObjectType>::StringToObject, jsonManipulator.get(), std::placeholders::_1),
                        std::bind(&JsonTester<ObjectType>::objectToStringCStr, this, std::placeholders::_1));
            };

            testConversion<std::string, decltype(binaryToObject2XWrapper)>(input, binaryToObject2XWrapper);
        }

        void testObjectConversion(const ObjectType& input) const {
            const auto ObjectToBinary2XWrapper = [this](const ObjectType& input) -> std::optional<std::pair<std::string, std::string>> {
                return this->objectToBinary2X(
                        input,
                        std::bind(&JsonManipulator<ObjectType>::ObjectToString, jsonManipulator.get(), std::placeholders::_1),
                        std::bind(&JsonManipulator<ObjectType>::StringToObject, jsonManipulator.get(), std::placeholders::_1));
            };

            testConversion<ObjectType, decltype(ObjectToBinary2XWrapper)>(input, ObjectToBinary2XWrapper);
        }

        void testObjectConversionCStr(const ObjectType& input) {
            const auto ObjectToBinary2XWrapper = [this](const ObjectType& input) -> std::optional<std::pair<std::string, std::string>> {
                return this->objectToBinary2X(
                        input,
                        std::bind(&JsonTester<ObjectType>::objectToStringCStr, this, std::placeholders::_1),
                        std::bind(&JsonManipulator<ObjectType>::StringToObject, jsonManipulator.get(), std::placeholders::_1));
            };

            testConversion<ObjectType, decltype(ObjectToBinary2XWrapper)>(input, ObjectToBinary2XWrapper);
        }

        ObjectType& getReference(datasource::Datasource& ds) {
            const auto slotIdx = ds.GetChoice() % 2;
            ObjectType& startRef = slots[slotIdx];

            auto ret = std::ref(startRef);

            while ( true ) {
                if ( ds.Get<bool>() == true ) {
                    break;
                }
                const auto isObject = jsonManipulator->IsObject(ret.get());
                if ( isObject && *isObject ) {
                    const auto memberNames = jsonManipulator->GetMemberNames(ret.get());
                    const size_t objectSize = memberNames->size();

                    if ( objectSize == 0 ) {
                        break;
                    }

                    const uint64_t whichMember = ds.Get<uint64_t>() % objectSize;
                    const auto memberName = (*memberNames)[whichMember];

                    const auto hasMember = jsonManipulator->HasMember(ret.get(), memberName);
                    if ( hasMember && *hasMember == false ) {
                        throw exception::LogicException("Member expected");
                    }

                    ret = jsonManipulator->GetMemberReference(std::ref(ret.get()), memberName);
                } else {
                    const auto isArray = jsonManipulator->IsArray(ret.get());
                    if ( isArray && *isArray ) {
                        const auto arraySize = jsonManipulator->GetArraySize(ret.get());
                        if ( !arraySize || *arraySize == 0 ) {
                            break;
                        }
                        const uint64_t index = ds.Get<uint64_t>() % *arraySize;

                        ret = jsonManipulator->GetMemberReference(std::ref(ret.get()), index);
                    } else {
                        break;
                    }
                }
            }
            return ret.get();
        }

        /* Start tests */
        void test_StringConversion(datasource::Datasource& ds) {
            const auto input = ds.Get<std::string>();
            if ( ds.Get<bool>() == true ) {
                testStringConversion(input);
            } else {
                testStringConversionCStr(input);
            }
        }

        void test_Comparison(datasource::Datasource& ds) {
            const auto& input1 = getReference(ds);
            const auto& input2 = getReference(ds);

            const auto EQ = jsonManipulator->IsEqual(input1, input2);
            const auto GT = jsonManipulator->IsGreaterThan(input1, input2);
            const auto LT = jsonManipulator->IsLessThan(input1, input2);
            const auto EQGT = jsonManipulator->IsEqualOrGreaterThan(input1, input2);
            const auto EQLT = jsonManipulator->IsEqualOrLessThan(input1, input2);

            if ( fuzzing::truth::isValid( {EQ, GT, LT, EQGT, EQLT} ) == false ) {
                TargetException("Incongruent truth values");
            }
        }

        void test_Clear(datasource::Datasource& ds) {
            auto& input = getReference(ds);

            jsonManipulator->Clear(input);
        }

        void test_Copy(datasource::Datasource& ds) {
            const auto& input = getReference(ds);

            const auto copy = jsonManipulator->Copy(input);
            if ( !copy ) {
                return;
            }

            if ( input != *copy ) {
                TargetException("Copy mismatch (1)");
            }

            const auto isEQ = jsonManipulator->IsEqual(input, *copy);
            if ( isEQ ) {
                if ( !(*isEQ) ) {
                    TargetException("Copy mismatch (2)");
                }
            }
        }

        void action_ConvertInto(datasource::Datasource& ds) {
            const auto input = ds.Get<std::string>();
            const auto obj = jsonManipulator->StringToObject(input);
            if ( !obj ) {
                return;
            }

            auto& dest = getReference(ds);
            jsonManipulator->Set(dest, *obj);
        }

        void test_SetKey(datasource::Datasource& ds) {
            auto& dest = getReference(ds);

            /* Only attempt to set a key in an object */
            if ( jsonManipulator->IsObject(dest) == false ) {
                return;
            }

            const auto key = ds.Get<std::string>();

            if ( jsonManipulator->SetKey(dest, key) == false ) {
                return;
            }

            const auto hasMember = jsonManipulator->HasMember(dest, key);
            if ( hasMember && *hasMember == false ) {
                TargetException("Expected key");
            }
        }

        void test_AssignRefToRef(datasource::Datasource& ds) {
            const auto& src = getReference(ds);
            auto& dest = getReference(ds);

            jsonManipulator->Set(dest, src);
        }

        void test_SetDouble(datasource::Datasource& ds) {
            auto& dest = getReference(ds);
            const auto val = ds.Get<double>();

            if ( std::isnan(val) == true ) {
                return;
            }

            if ( jsonManipulator->SetDouble(dest, val) == false ) {
                return;
            }

            const auto isNumber = jsonManipulator->IsNumber(dest);

            if ( isNumber && *isNumber == false ) {
                TargetException("Expected type to be number");
            }

            const auto res = jsonManipulator->GetDouble(dest);
            if ( res && *res != val ) {
                TargetException("SetDouble mismatch");
            }

            testObjectConversion(dest);
        }


        void test_SetInt32(datasource::Datasource& ds) {
            auto& dest = getReference(ds);
            const auto val = ds.Get<int32_t>();

            if ( jsonManipulator->SetInt32(dest, val) == false ) {
                return;
            }

            const auto isNumber = jsonManipulator->IsNumber(dest);

            if ( isNumber && *isNumber == false ) {
                TargetException("Expected type to be number");
            }

            const auto res = jsonManipulator->GetInt32(dest);
            if ( res && *res != val ) {
                TargetException("SetInt32 mismatch");
            }

            testObjectConversion(dest);
        }

        void test_SetInt64(datasource::Datasource& ds) {
            auto& dest = getReference(ds);
            const auto val = ds.Get<int64_t>();

            if ( jsonManipulator->SetInt64(dest, val) == false ) {
                return;
            }

            const auto isNumber = jsonManipulator->IsNumber(dest);

            if ( isNumber && *isNumber == false ) {
                TargetException("Expected type to be number");
            }

            const auto res = jsonManipulator->GetInt64(dest);
            if ( res && *res != val ) {
                TargetException("SetInt64 mismatch");
            }
            testObjectConversion(dest);
        }

        void test_ObjectConversion(datasource::Datasource& ds) {
            const auto input = getReference(ds);
            if ( ds.Get<bool>() == true ) {
                testObjectConversion(input);
            } else {
                testObjectConversionCStr(input);
            }
        }

        void test_Swap(datasource::Datasource& ds) {
            auto& input1 = getReference(ds);
            auto& input2 = getReference(ds);
            jsonManipulator->Swap(input1, input2);
        }

        ObjectType& set(ObjectType& input, datasource::Datasource& ds) {
            if ( jsonManipulator->IsNull(input) == true ) {
            } else if ( jsonManipulator->IsObject(input) == true ) {
                const auto key = ds.Get<std::string>();
                /* TODO non-recursive */
                const auto val = construct(ds);
                /* jsonManipulator->ObjectInsert(val); */
            } else if ( jsonManipulator->IsArray(input) == true ) {
                /* TODO non-recursive */
                const auto val = construct(ds);
                /* jsonManipulator->ArrayInsert(val); */
            } else if ( jsonManipulator->IsString(input) == true ) {
                const auto val = ds.Get<std::string>();
                /* jsonManipulator->SetString(val); */
            } else if ( jsonManipulator->IsNumber(input) == true ) {
                /* setNumber(input, ds); */
            } else if ( jsonManipulator->IsBoolean(input) == true ) {
                const auto val = ds.Get<bool>();
                /* jsonManipulator->SetBoolean(val); */
            }
        }

        void construct(datasource::Datasource& ds) {
            ObjectType root;
            ObjectType& rootRef = root;
            std::set<ObjectType&> nodes{rootRef};
            while ( ds.Get<bool>() == true ) {
                ObjectType& curRef = nodes[ds.Get<uint16_t>() % nodes.size()];

                const auto action = ds.GetChoice();
                switch ( action ) {
                    case    0:
                        {
                            /* jsonManipulator->SetNull */
                        }
                        break;
                    case    1:
                        {
                            /* jsonManipulator->SetObject */
                        }
                        break;
                    case    2:
                        {
                            /* jsonManipulator->SetArray */
                        }
                        break;
                    case    3:
                        {
                            /* jsonManipulator->SetString */
                        }
                        break;
                    case    4:
                        {
                            /* jsonManipulator->SetNumber */
                        }
                        break;
                    case    5:
                        {
                            /* jsonManipulator->SetBoolean */
                        }
                        break;
                    case    6:
                        {
                            nodes.insert( set(curRef, ds) );
                        }
                        break;
                }
            }
        }

    public:
        JsonTester(std::unique_ptr<JsonManipulator<ObjectType>> jsonManipulator) :
            SerializeTester<ObjectType, std::string>(),
            mt(
                new Multitest(
                    {
                      SingleTest(std::bind(&JsonTester::test_StringConversion, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_Comparison, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_Clear, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_Copy, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::action_ConvertInto, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_SetKey, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_AssignRefToRef, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_SetDouble, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_SetInt32, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_ObjectConversion, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_SetInt64, this, std::placeholders::_1)),
                      SingleTest(std::bind(&JsonTester::test_Swap, this, std::placeholders::_1)),
                    }
                )
            ),
            jsonManipulator(std::move(jsonManipulator))
            {}

        void Test(datasource::Datasource& ds, const size_t numLoops = 5) {
            /* Reset state */
            if ( jsonManipulator->Clear(slots[0]) == false ) {
                throw exception::LogicException("Failed to clear JSON object slot");
            }
            if ( jsonManipulator->Clear(slots[1]) == false ) {
                throw exception::LogicException("Failed to clear JSON object slot");
            }

            for (size_t i = 0; i < numLoops; i++) {
                mt->Test(ds);
            }
        }
};

} /* namespace fuzzing */

#endif
