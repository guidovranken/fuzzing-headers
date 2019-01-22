#include <fuzzing/json.hpp>
#include "json.hpp"

class NlohmannJsonManipulator : public fuzzing::JsonManipulator<nlohmann::json> {
    public:
        NlohmannJsonManipulator(void) : fuzzing::JsonManipulator<nlohmann::json>() { }
        ~NlohmannJsonManipulator() override = default;

        std::optional<nlohmann::json> StringToObject(const std::string& input) override {
            return nlohmann::json::parse(input);
        }

        std::optional<std::string> ObjectToString(const nlohmann::json& input) override {
            return input.dump();
        }

        std::optional<bool> IsEqual(const nlohmann::json& input1, const nlohmann::json& input2) override {
            return input1 == input2;
        }

        std::optional<bool> IsGreaterThan(const nlohmann::json& input1, const nlohmann::json& input2) override {
            return input1 > input2;
        }

        std::optional<bool> IsLessThan(const nlohmann::json& input1, const nlohmann::json& input2) override {
            return input1 < input2;
        }

        std::optional<bool> IsEqualOrGreaterThan(const nlohmann::json& input1, const nlohmann::json& input2) override {
            return input1 >= input2;
        }

        std::optional<bool> IsEqualOrLessThan(const nlohmann::json& input1, const nlohmann::json& input2) override {
            return input1 <= input2;
        }

        bool Clear(nlohmann::json& input) override {
            input.clear();

            return true;
        }

        std::optional<bool> IsObject(const nlohmann::json& input) override {
            return input.is_object();
        }

        std::optional<bool> IsArray(const nlohmann::json& input) override {
            return input.is_array();
        }

        std::optional<bool> IsString(const nlohmann::json& input) override {
            return input.is_string();
        }

        std::optional<bool> IsNumber(const nlohmann::json& input) override {
            return input.is_number();
        }

        std::optional<bool> IsBoolean(const nlohmann::json& input) override {
            return input.is_boolean();
        }

        std::optional<uint64_t> GetArraySize(const nlohmann::json& input) override {
            return input.size();
        }

        std::optional<std::vector<std::string>> GetMemberNames(const nlohmann::json& input) override {
            std::vector<std::string> ret;

            for (auto it = input.begin(); it < input.end(); it++) {
                ret.push_back( it.key() );
            }

            return ret;
        }

        std::optional<nlohmann::json> Copy(const nlohmann::json& input) override {
            return nlohmann::json(input);
        }
};

std::unique_ptr<fuzzing::JsonTester<nlohmann::json>> jsonTester;

extern "C" int LLVMFuzzerInitialize(int *_argc, char ***_argv) {
    (void)_argc;
    (void)_argv;

    jsonTester = std::make_unique<fuzzing::JsonTester<nlohmann::json>>( std::make_unique<NlohmannJsonManipulator>() );

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzzing::Datasource ds(data, size);

    try {
        jsonTester->Test(ds);
    } catch ( ... ) { }

    return 0;
}
