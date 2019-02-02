#ifndef FUZZING_TESTERS_SERIALIZE_DIFFERENTIAL_HPP
#define FUZZING_TESTERS_SERIALIZE_DIFFERENTIAL_HPP

#include <fuzzing/datasource/datasource.hpp>
#include <memory>
#include <vector>
#include <optional>
#include <functional>
#include <string>
#include <utility>

namespace fuzzing {
namespace testers {
namespace differential {

struct UniversalBase {
    virtual void Load(datasource::Datasource& ds) = 0;
    virtual ~UniversalBase() = default;
};

template <class T>
struct UniversalFromGeneric : public UniversalBase {
    T v;
    UniversalFromGeneric(void) = default;
    UniversalFromGeneric(T v) : v(v) { }
    void Load(datasource::Datasource& ds) override {
        v = ds.Get<T>();
    }
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
        virtual std::optional<UniversalOutput> Run(const UniversalInput& input) const = 0;
};

template <typename UniversalInput, typename UniversalOutput, bool Multi, class... Targets>
class DifferentialTester {
    static_assert(std::is_base_of<UniversalBase, UniversalInput>::value);
    static_assert(std::is_base_of<UniversalBase, UniversalOutput>::value);
    protected:
        template<std::size_t I = 0, typename... Tp> inline typename std::enable_if<I == sizeof...(Tp), void>::type RunTarget(
                const UniversalInput& input,
                std::vector<std::optional<UniversalOutput>>& results,
                std::vector<size_t>& successfulRuns,
                std::tuple<Tp...>& t) {
            (void)input;
            (void)results;
            (void)successfulRuns,
            (void)t;
        }

        template<std::size_t I = 0, typename... Tp> inline typename std::enable_if<I < sizeof...(Tp), void>::type RunTarget(
                const UniversalInput& input,
                std::vector<std::optional<UniversalOutput>>& results,
                std::vector<size_t>& successfulRuns,
                std::tuple<Tp...>& t) {
            results[I] = std::get<I>(t).Run(input);
            if ( results[I] != std::nullopt ) {
                successfulRuns.push_back(I);
            }
            RunTarget<I + 1, Tp...>(input, results, successfulRuns, t);
        }

    public:
        DifferentialTester(void) = default;
        ~DifferentialTester(void) = default;

        bool Run(datasource::Datasource& ds) {
            /* Instantiate each target class */
            std::tuple<Targets...> targets;

            constexpr size_t numTargets = std::tuple_size<decltype(targets)>::value;

            UniversalInput input;
            input.Load(ds);

            do {
                std::vector<std::optional<UniversalOutput>> results(numTargets);
                std::vector<size_t> successfulRuns;

                /* Run 'results[i] = target.Run(input)' for each target */
                RunTarget(input, results, successfulRuns, targets);

                if ( successfulRuns.size() >= 2 ) {
                    for (size_t i = 0; i < successfulRuns.size() - 1; i++) {
                        const size_t curIndex = successfulRuns[i];
                        const size_t nextIndex = successfulRuns[i+1];
                        if ( *(results[curIndex]) != *(results[nextIndex]) ) {
                            /* TODO call crash callback */
                            printf("(crash)\n");
                            return false;
                        }
                    }
                }
            } while ( Multi == true );

            return true;
        }
};

template <typename UniversalInput, typename UniversalOutput, class... Targets>
using DifferentialTesterSingle = DifferentialTester<UniversalInput, UniversalOutput, false, Targets...>;

template <typename UniversalInput, typename UniversalOutput, class... Targets>
using DifferentialTesterMulti = DifferentialTester<UniversalInput, UniversalOutput, true, Targets...>;

} /* namespace differential */
} /* namespace testers */
} /* namespace fuzzing */

#endif
