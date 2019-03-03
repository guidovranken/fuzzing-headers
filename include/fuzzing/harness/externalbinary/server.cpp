#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include "shared.hpp"

#ifdef __linux__
__attribute__((section("__libfuzzer_extra_counters")))
#endif
static uint8_t Counters[kNumPCs];

namespace fuzzing {
namespace harness {
namespace externalbinary {

class ExternalBinaryExecutor {
    private:
        const std::string program;
        const std::string pidStr;
        size_t counter = 0;
        std::string lastDumpfile;

        std::string getDumpfile(void) {
            counter++;
            const std::string ret = "COUNTER_DUMPFILE_" + pidStr + "_" + std::to_string(counter);
            lastDumpfile = ret;
            return ret;
        }

    public:
        ExternalBinaryExecutor(const std::string program) :
            program(program), pidStr( std::to_string(getpid()) )
        { }

        bool Run(void) {
            const auto dumpfile = getDumpfile();
            unlink(dumpfile.c_str());

            if ( setenv("FUZZER_COUNTER_DUMP_FILE", dumpfile.c_str(), 1) != 0 ) {
                abort();
            }
            return system(program.c_str()) == 0;
        }

        bool LoadCounters(void) {
            const auto dumpfile = lastDumpfile;
            FILE* fp = fopen(dumpfile.c_str(), "rb");
            if ( fp == nullptr ) {
                return false;
            }

            bool ret = false;
            uint8_t _Counters[kNumPCs];
            if ( fread(_Counters, kNumPCs, 1, fp) != 1 ) {
                goto end;
            }

            memcpy(Counters, _Counters, kNumPCs);

            ret = true;
end:
            fclose(fp);

            return ret;
        }

};

} /* namespace externalbinary */
} /* namespace harness */
} /* namespace fuzzing */

/*
 * testing
int main(void)
{
    ExternalBinaryExecutor ex("./program");
    ex.Run();
    printf("%d\n", ex.LoadCounters());
}
*/
