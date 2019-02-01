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
        TestDifferentialTester(std::initializer_list<std::shared_ptr<DifferentialTarget<std::string, std::string>>> targets) : DifferentialTester(targets) { }
};

class TestDifferentialTargetOne : public DifferentialTarget<std::string, std::string> {
    public:
        void Start(void) override { };
        std::optional<std::string> Run(const std::string& input) const override { return "One"; }
};

class TestDifferentialTargetTwo : public DifferentialTarget<std::string, std::string> {
    public:
        void Start(void) override { };
        std::optional<std::string> Run(const std::string& input) const override { return "Two"; }
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
