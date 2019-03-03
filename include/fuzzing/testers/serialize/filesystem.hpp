#pragma once

#include <fuzzing/datasource/datasource.hpp>
#include <fuzzing/datasource/id.hpp>
#include <fuzzing/generators/filesystem.hpp>
#include <stdlib.h>

namespace fuzzing {
namespace testers {
namespace filesystem {

class FilesystemTester {
    protected:
        datasource::Datasource& ds;
        const std::string fsRootPath;
        virtual bool transform(void) = 0;
    private:
        const fuzzing::generators::filesystem::Filesystem fs;
    public:
        FilesystemTester(datasource::Datasource& ds, const std::string fsRootPath) :
            ds(ds), fsRootPath(fsRootPath), fs(ds, fsRootPath)
        { }

        bool Run(void) {
            if ( fs.Write() == false ) {
                return false;
            }

            if ( fs.Verify() == false ) {
                return false;
            }

            if ( transform() == false ) {
                return true;
            }

            if ( fs.Verify() == false ) {
                return false;
            }

            if ( fs.Remove() == false ) {
                return false;
            }

            return true;
        }
};

class TarTester : public fuzzing::testers::filesystem::FilesystemTester {
    private:
        bool transform(void) {
            {
                static const auto createTarCmd = std::string("tar cf archive.tar " + fsRootPath + "/");
                if ( system(createTarCmd.c_str()) != 0 ) {
                    abort();
                }
            }

            {
                static const auto rmdirCmd = std::string("rm -rf " + fsRootPath + "/");
                if ( system(rmdirCmd.c_str()) != 0 ) {
                    abort();
                }
            }

            {
                static const auto extractCmd = std::string("tar xf archive.tar");
                if ( system(extractCmd.c_str()) != 0 ) {
                    abort();
                }
            }

            {
                static const auto rmTarCmd = std::string("rm -rf archive.tar");
                if ( system(rmTarCmd.c_str()) != 0 ) {
                    abort();
                }
            }

            return true;
        }
    public:
        TarTester(fuzzing::datasource::Datasource& ds, const std::string fsRootPath) :
            fuzzing::testers::filesystem::FilesystemTester(ds, fsRootPath)
        { }
};

} /* namespace filesystem */
} /* namespace testers */
} /* namespace fuzzing */
