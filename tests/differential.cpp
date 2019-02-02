#include <fuzzing/testers/differential/differential.hpp>
#include <string>

using fuzzing::datasource::Datasource;
using fuzzing::testers::differential::UniversalFromGeneric;
using fuzzing::testers::differential::DifferentialTesterSingle;
using fuzzing::testers::differential::DifferentialTarget;

using TestUniversalInput = UniversalFromGeneric<std::string>;
using TestUniversalOutput = UniversalFromGeneric<std::string>;

template <class... Targets>
using TestDifferentialTester = DifferentialTesterSingle<TestUniversalInput, TestUniversalOutput, Targets...>;

class TestDifferentialTargetOne : public DifferentialTarget<TestUniversalInput, TestUniversalOutput> {
    public:
        std::optional<TestUniversalOutput> Run(const TestUniversalInput& input) const override { return TestUniversalOutput("One"); }
};

class TestDifferentialTargetTwo : public DifferentialTarget<TestUniversalInput, TestUniversalOutput> {
    public:
        std::optional<TestUniversalOutput> Run(const TestUniversalInput& input) const override { return TestUniversalOutput("Two"); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Datasource ds(data, size);

    TestDifferentialTester<
        TestDifferentialTargetOne,
        TestDifferentialTargetTwo
    > diff;

    try {
        diff.Run(ds);
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
    return 0;
}
