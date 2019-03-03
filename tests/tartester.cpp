#include <fuzzing/testers/serialize/filesystem.hpp>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzzing::datasource::Datasource ds(data, size);
    try {
        fuzzing::testers::filesystem::TarTester fs(ds, "fsroot");
        if ( fs.Run() == false ) {
            abort();
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    } catch ( fuzzing::generators::filesystem::FlowException ) {
    } catch ( ... ) {
    }

    return 0;
}
