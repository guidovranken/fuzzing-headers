#ifndef FUZZING_TESTERS_SERIALIZE_DIFFERENTIAL_HPP
#define FUZZING_TESTERS_SERIALIZE_DIFFERENTIAL_HPP

#include <fuzzing/datasource/datasource.hpp>
#include <memory>
#include <vector>
#include <optional>
#include <functional>
#include <string>

namespace fuzzing {
namespace testers {
namespace differential {

struct UniversalBase {
};

template <class T>
struct UniversalFromGeneric : public UniversalBase {
    T v;
    UniversalFromGeneric(T v) : v(v) { }
    bool operator!=(const UniversalFromGeneric<T>& other) const {
        return v != other.v;
    }
};

template <typename UniversalInput, typename UniversalOutput>
class DifferentialTarget {
    static_assert(std::is_base_of<UniversalBase, UniversalInput>::value);
    static_assert(std::is_base_of<UniversalBase, UniversalOutput>::value);
    public:
        DifferentialTarget(void) = default;
        virtual ~DifferentialTarget(void) = default;
        virtual void Start(void) = 0;
        virtual std::optional<UniversalOutput> Run(const UniversalInput& input) const = 0;
};


template <typename UniversalInput, typename UniversalOutput>
class DifferentialTester {
    static_assert(std::is_base_of<UniversalBase, UniversalInput>::value);
    static_assert(std::is_base_of<UniversalBase, UniversalOutput>::value);
    protected:
        virtual UniversalInput DSToUniversalInput(datasource::Datasource& ds) const = 0;
    private:
        std::vector<std::shared_ptr<DifferentialTarget<UniversalInput, UniversalOutput>>> targets;

        bool compare(const std::vector<std::optional<UniversalOutput>> results) {
            std::vector<size_t> success;

            for (size_t i = 0; i < results.size(); i++) {
                if ( results[i] != std::nullopt ) {
                    success.push_back(i);
                }
            }

            if ( success.size() < 2 ) {
                /* Nothing to compare */
                return true;
            }

            for (size_t i = 0; i < success.size() - 1; i++) {
                const size_t curIndex = success[i];
                const size_t nextIndex = success[i+1];
                if ( *(results[curIndex]) != *(results[nextIndex]) ) {
                    return false;
                }
            }

            return true;
        }
    public:
        DifferentialTester(std::initializer_list<std::shared_ptr<DifferentialTarget<UniversalInput, UniversalOutput>>> targets) : targets(targets) { };
        bool Run(datasource::Datasource& ds) {
            std::vector<std::optional<UniversalOutput>> results(targets.size());

            const auto input = DSToUniversalInput(ds);

            for (size_t i = 0; i < targets.size(); i++) {
                auto& curTarget = targets[i];
                curTarget->Start();
            }

            size_t numFailed = 0;
            for (size_t i = 0; i < targets.size(); i++) {
                auto& curTarget = targets[i];
                results[i] = curTarget->Run(input);
                
                numFailed += results[i] == std::nullopt ? 1 : 0;
            }

            if ( numFailed == targets.size() ) {
                /* All failed */

                return false;
            }

            if ( compare(results) == false ) {
                printf("KRESH\n");
                /* TODO call crash callback */
                return false;
            }

            return true;
        }
};

} /* namespace differential */
} /* namespace testers */
} /* namespace fuzzing */

#endif
