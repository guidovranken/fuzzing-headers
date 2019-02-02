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

template <typename UniversalInput, typename UniversalOutput, class... Targets>
class DifferentialTester {
    static_assert(std::is_base_of<UniversalBase, UniversalInput>::value);
    static_assert(std::is_base_of<UniversalBase, UniversalOutput>::value);
    protected:

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

        template<std::size_t I = 0, typename... Tp> inline typename std::enable_if<I == sizeof...(Tp), void>::type RunTarget(
                const UniversalInput& input,
                std::vector<std::optional<UniversalOutput>>& results,
                std::tuple<Tp...>& t) {
            (void)input;
            (void)results;
            (void)t;
        }

        template<std::size_t I = 0, typename... Tp> inline typename std::enable_if<I < sizeof...(Tp), void>::type RunTarget(
                const UniversalInput& input,
                std::vector<std::optional<UniversalOutput>>& results,
                std::tuple<Tp...>& t) {
            results[I] = std::get<I>(t).Run(input);
            RunTarget<I + 1, Tp...>(input, results, t);
        }

    public:
        DifferentialTester(void) = default;
        ~DifferentialTester(void) = default;

        bool Run(datasource::Datasource& ds) {
            std::tuple<Targets...> tuple_;
            const size_t targetSize = std::tuple_size<decltype(tuple_)>::value;
            std::vector<std::optional<UniversalOutput>> results(targetSize);

            UniversalInput input;
            input.Load(ds);

            RunTarget(input, results, tuple_);

            if ( compare(results) == false ) {
                /* TODO call crash callback */
                printf("(crash)\n");
                return false;
            }

            return true;
        }
};

} /* namespace differential */
} /* namespace testers */
} /* namespace fuzzing */

#endif
