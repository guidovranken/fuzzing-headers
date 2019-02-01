#include <fuzzing/testers/differential/differential.hpp>
#include <string>

using fuzzing::datasource::Datasource;
using fuzzing::testers::differential::DifferentialTester;
using fuzzing::testers::differential::DifferentialTarget;

class TestDifferentialTester : public DifferentialTester<std::string, std::string> {
    private:
        std::string DSToUniversalInput(Datasource& ds) const override {
            return ds.Get<std::string>();
        }
    public:
        TestDifferentialTester(std::initializer_list<DifferentialTarget<std::string, std::string>> targets) : DifferentialTester(targets) { }
};

std::optional<std::string> TargetOne(const std::string& input) {
    return "One";
}

std::optional<std::string> TargetTwo(const std::string& input) {
    return "Two";
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Datasource ds(data, size);

    TestDifferentialTester diff( {DifferentialTarget<std::string, std::string>(TargetOne), DifferentialTarget<std::string, std::string>(TargetTwo)} );
    try {
        diff.Run(ds);
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
    return 0;
}
