#include <fuzzing/testers/differential/differential.hpp>
#include <string>

using fuzzing::datasource::Datasource;
using fuzzing::testers::differential::UniversalFromGeneric;
using fuzzing::testers::differential::DifferentialTester;
using fuzzing::testers::differential::DifferentialTarget;

using TestUniversalInput = UniversalFromGeneric<std::string>;
using TestUniversalOutput = UniversalFromGeneric<std::string>;

class TestDifferentialTester : public DifferentialTester<TestUniversalInput, TestUniversalOutput> {
    private:
        TestUniversalInput DSToUniversalInput(Datasource& ds) const override {
            return TestUniversalInput(ds.Get<std::string>());
        }
    public:
        TestDifferentialTester(std::initializer_list<std::shared_ptr<DifferentialTarget<TestUniversalInput, TestUniversalOutput>>> targets) : DifferentialTester(targets) { }
};

class TestDifferentialTargetOne : public DifferentialTarget<TestUniversalInput, TestUniversalOutput> {
    public:
        void Start(void) override { };
        std::optional<TestUniversalOutput> Run(const TestUniversalInput& input) const override { return TestUniversalOutput("One"); }
};

class TestDifferentialTargetTwo : public DifferentialTarget<TestUniversalInput, TestUniversalOutput> {
    public:
        void Start(void) override { };
        std::optional<TestUniversalOutput> Run(const TestUniversalInput& input) const override { return TestUniversalOutput("Two"); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Datasource ds(data, size);

    TestDifferentialTester diff({
            std::make_shared<TestDifferentialTargetOne>(),
            std::make_shared<TestDifferentialTargetTwo>(),
            });
    try {
        diff.Run(ds);
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
    return 0;
}
