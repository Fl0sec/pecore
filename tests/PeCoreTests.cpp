#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <pecore/PeFastWrapper.h>
#include <vector>
#include <cstring>

namespace {

    // Builds a minimal but well-formed synthetic PE header (no sections, no data
    // directories) so validation logic can be exercised without touching a real module.
    std::vector<std::byte> makeMinimalValidPe( WORD magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC ) {
        std::vector<std::byte> buf( 0x200, std::byte{ 0 } );

        auto dos = reinterpret_cast< IMAGE_DOS_HEADER* >( buf.data( ) );
        dos->e_magic = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = 0x80;

        auto nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( buf.data( ) + 0x80 );
        nt->Signature = IMAGE_NT_SIGNATURE;
        nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt->FileHeader.NumberOfSections = 0;
        nt->FileHeader.SizeOfOptionalHeader = sizeof( IMAGE_OPTIONAL_HEADER64 );
        nt->FileHeader.Characteristics = IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE;
        nt->OptionalHeader.Magic = magic;
        nt->OptionalHeader.NumberOfRvaAndSizes = 0;

        return buf;
    }

}

TEST_CASE( "from() rejects a null base" ) {
    CHECK_FALSE( PeFastWrapper::from( nullptr ).has_value( ) );
}

TEST_CASE( "from() rejects a bad DOS signature" ) {
    unsigned char buf[64] = { };
    buf[0] = 'X';
    buf[1] = 'X';
    CHECK_FALSE( PeFastWrapper::from( buf ).has_value( ) );
}

TEST_CASE( "from() rejects an out-of-range e_lfanew" ) {
    std::vector<std::byte> buf( 0x40, std::byte{ 0 } );
    auto dos = reinterpret_cast< IMAGE_DOS_HEADER* >( buf.data( ) );
    dos->e_magic = IMAGE_DOS_SIGNATURE;

    SUBCASE( "negative" ) {
        dos->e_lfanew = -1;
        CHECK_FALSE( PeFastWrapper::from( buf.data( ) ).has_value( ) );
    }

    SUBCASE( "absurdly large" ) {
        dos->e_lfanew = 0x7FFFFFFF;
        CHECK_FALSE( PeFastWrapper::from( buf.data( ) ).has_value( ) );
    }
}

TEST_CASE( "from() rejects a bad NT signature" ) {
    std::vector<std::byte> buf( 0x100, std::byte{ 0 } );
    auto dos = reinterpret_cast< IMAGE_DOS_HEADER* >( buf.data( ) );
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x40;

    std::memcpy( buf.data( ) + 0x40, "NOPE", 4 );

    CHECK_FALSE( PeFastWrapper::from( buf.data( ) ).has_value( ) );
}

TEST_CASE( "from() rejects an unrecognized optional header Magic" ) {
    auto buf = makeMinimalValidPe( 0xFFFF );
    CHECK_FALSE( PeFastWrapper::from( buf.data( ) ).has_value( ) );
}

TEST_CASE( "from() accepts a minimal well-formed synthetic PE" ) {
    auto buf = makeMinimalValidPe( );
    auto wrapper = PeFastWrapper::from( buf.data( ) );

    REQUIRE( wrapper.has_value( ) );
    CHECK( wrapper->isDLL( ) );
    CHECK( wrapper->getArch( ) == Architecture::X64 );
    CHECK( wrapper->getExport( "AnyExport" ) == nullptr );
    CHECK( wrapper->getImportDescriptors( ).empty( ) );
    CHECK( wrapper->getSectionHeaders( ).empty( ) );
}

TEST_CASE( "real module: kernel32.dll" ) {
    auto mod = LoadLibraryA( "kernel32.dll" );
    REQUIRE( mod != nullptr );

    auto wrapper = PeFastWrapper::from( mod );
    REQUIRE( wrapper.has_value( ) );

    CHECK( wrapper->isDLL( ) );
    CHECK_FALSE( wrapper->isEXE( ) );
    CHECK( wrapper->isExecutableImage( ) );
    CHECK( wrapper->getEntryPointRVA( ).has_value( ) );
    CHECK( wrapper->getImageBase( ).has_value( ) );
    CHECK( wrapper->getSizeOfImage( ).has_value( ) );

#if defined( _WIN64 )
    CHECK( wrapper->getArch( ) == Architecture::X64 );
#else
    CHECK( wrapper->getArch( ) == Architecture::X86 );
#endif

    SUBCASE( "exports resolve" ) {
        CHECK( wrapper->getExport( "LoadLibraryA" ) != nullptr );
        CHECK( wrapper->getExport( "GetProcAddress" ) != nullptr );
        CHECK( wrapper->getExport( "ThisExportDoesNotExist_1234" ) == nullptr );
    }

    SUBCASE( "imports are non-empty and named" ) {
        auto imports = wrapper->getImportDescriptors( );
        CHECK_FALSE( imports.empty( ) );

        for ( const auto& descriptor : imports )
        {
            CHECK_FALSE( wrapper->getImportedModuleName( descriptor ).empty( ) );
        }
    }

    SUBCASE( "every section is self-consistent with getSectionContaining" ) {
        auto sections = wrapper->getSectionHeaders( );
        CHECK_FALSE( sections.empty( ) );

        for ( const auto& section : sections )
        {
            CHECK( wrapper->getSectionContaining( section.VirtualAddress ) == &section );
        }
    }

    SUBCASE( "named section spans stay within the mapped image" ) {
        const auto imageSize = static_cast<std::size_t>( *wrapper->getSizeOfImage( ) );

        for ( const auto& section : wrapper->getSectionHeaders( ) )
        {
            const std::string_view name { reinterpret_cast<const char*>( section.Name ), IMAGE_SIZEOF_SHORT_NAME };
            const auto trimmedName = name.substr( 0, name.find( '\0' ) );
            if ( trimmedName.empty( ) )
                continue;

            const auto span = wrapper->getSectionByName( trimmedName, 0 );
            REQUIRE_FALSE( span.empty( ) );
            CHECK( span.data( ) >= reinterpret_cast<const std::byte*>( mod ) );
            CHECK( span.size( ) <= imageSize );
            CHECK( static_cast<std::size_t>( span.data( ) - reinterpret_cast<const std::byte*>( mod ) ) + span.size( ) <= imageSize );
        }
    }

    SUBCASE( "PDB70 info, if present, looks sane" ) {
        if ( auto pdb = wrapper->getPdb70Info( ) )
        {
            CHECK_FALSE( pdb->pdbPath.empty( ) );
        }
    }
}

TEST_CASE( "real module: the test executable itself" ) {
    auto wrapper = PeFastWrapper::from( GetModuleHandle( nullptr ) );
    REQUIRE( wrapper.has_value( ) );

    CHECK( wrapper->isEXE( ) );
    CHECK_FALSE( wrapper->isDLL( ) );
    CHECK_FALSE( wrapper->isManagedAssembly( ) );
    CHECK( wrapper->getCor20Header( ) == nullptr );

    SUBCASE( "own PDB70 info is present (the build always links with /DEBUG)" ) {
        auto pdb = wrapper->getPdb70Info( );
        REQUIRE( pdb.has_value( ) );
        CHECK_FALSE( pdb->pdbPath.empty( ) );
        CHECK( pdb->pdbPath.ends_with( ".pdb" ) );
    }

    SUBCASE( "load config directory matches host bitness" ) {
        auto loadConfig = wrapper->getLoadConfig( );
        REQUIRE( loadConfig.has_value( ) );

#if defined( _WIN64 )
        CHECK( std::holds_alternative<const IMAGE_LOAD_CONFIG_DIRECTORY64*>( *loadConfig ) );
#else
        CHECK( std::holds_alternative<const IMAGE_LOAD_CONFIG_DIRECTORY32*>( *loadConfig ) );
#endif
    }

    SUBCASE( "relocations (ASLR is on by default) are within the image and well-typed" ) {
        auto relocations = wrapper->getRelocations( );
        auto sizeOfImage = wrapper->getSizeOfImage( );

        REQUIRE( sizeOfImage.has_value( ) );
        CHECK_FALSE( relocations.empty( ) );

        for ( const auto& reloc : relocations )
        {
            CHECK( reloc.rva < *sizeOfImage );
            CHECK( reloc.type <= IMAGE_REL_BASED_DIR64 );
        }
    }

    SUBCASE( "own imports are non-empty and each thunk is structurally valid" ) {
        auto imports = wrapper->getImportDescriptors( );
        CHECK_FALSE( imports.empty( ) );

        std::size_t totalFunctions = 0;

        for ( const auto& descriptor : imports )
        {
            CHECK_FALSE( wrapper->getImportedModuleName( descriptor ).empty( ) );

            for ( const auto& fn : wrapper->getImportedFunctions( descriptor ) )
            {
                if ( fn.byOrdinal )
                    CHECK( fn.name.empty( ) );
                else
                    CHECK_FALSE( fn.name.empty( ) );

                ++totalFunctions;
            }
        }

        CHECK( totalFunctions > 0 );
    }

    SUBCASE( "delay-import and bound-import directories are absent without crashing" ) {
        CHECK( wrapper->getDelayImportDescriptors( ).empty( ) );
        CHECK( wrapper->getBoundImportModules( ).empty( ) );
    }

    SUBCASE( "resource tree (embedded manifest) walks without crashing" ) {
        auto root = wrapper->getResourceRoot( );

        if ( root )
        {
            std::size_t leafCount = 0;

            for ( const auto& typeEntry : wrapper->getResourceEntries( root ) )
            {
                auto nameDir = wrapper->getResourceSubdirectory( typeEntry );
                CHECK( nameDir != nullptr );
                if ( !nameDir )
                    continue;

                for ( const auto& nameEntry : wrapper->getResourceEntries( nameDir ) )
                {
                    auto langDir = wrapper->getResourceSubdirectory( nameEntry );
                    CHECK( langDir != nullptr );
                    if ( !langDir )
                        continue;

                    for ( const auto& langEntry : wrapper->getResourceEntries( langDir ) )
                    {
                        auto dataEntry = wrapper->getResourceDataEntry( langEntry );
                        REQUIRE( dataEntry != nullptr );
                        CHECK( dataEntry->Size > 0 );
                        ++leafCount;
                    }
                }
            }

            CHECK( leafCount > 0 );
        }
    }
}

TEST_CASE( "getExport: ordinal branch handles underflow and out-of-range safely" ) {
    auto wrapper = PeFastWrapper::from( LoadLibraryA( "kernel32.dll" ) );
    REQUIRE( wrapper.has_value( ) );

    // exportDirectory->Base is typically 1; ordinal 0 makes (identifier - Base) wrap
    // around to a huge unsigned value, which must be rejected by the bounds check
    // rather than indexing out of the functions array.
    CHECK( wrapper->getExport( static_cast<WORD>( 0 ) ) == nullptr );
    CHECK( wrapper->getExport( static_cast<WORD>( 0xFFFF ) ) == nullptr );
}

TEST_CASE( "getExport: hint mismatches fall back to a correct full lookup" ) {
    auto wrapper = PeFastWrapper::from( LoadLibraryA( "kernel32.dll" ) );
    REQUIRE( wrapper.has_value( ) );

    auto withoutHint = wrapper->getExport( "LoadLibraryA" );
    REQUIRE( withoutHint != nullptr );

    SUBCASE( "wrong hint still resolves to the same address" ) {
        CHECK( wrapper->getExport( "LoadLibraryA", static_cast<WORD>( 0 ) ) == withoutHint );
    }

    SUBCASE( "out-of-range hint is ignored, not read out of bounds" ) {
        CHECK( wrapper->getExport( "LoadLibraryA", static_cast<WORD>( 0xFFFF ) ) == withoutHint );
    }
}

TEST_CASE( "getExport: name lookups are stable across the alphabet" ) {
    auto wrapper = PeFastWrapper::from( LoadLibraryA( "kernel32.dll" ) );
    REQUIRE( wrapper.has_value( ) );

    // Spans low/mid/high name-table positions -- useful today as a correctness
    // baseline, and specifically to catch a boundary mistake once the name lookup
    // switches from a linear scan to a binary search.
    CHECK( wrapper->getExport( "AddAtomA" ) != nullptr );
    CHECK( wrapper->getExport( "CreateFileW" ) != nullptr );
    CHECK( wrapper->getExport( "ExitProcess" ) != nullptr );
    CHECK( wrapper->getExport( "LoadLibraryA" ) != nullptr );
    CHECK( wrapper->getExport( "VirtualAlloc" ) != nullptr );
    CHECK( wrapper->getExport( "WriteFile" ) != nullptr );

    // Not present, but sorts near real entries -- must not resolve to a neighbour.
    CHECK( wrapper->getExport( "WriteFileZ_DoesNotExist" ) == nullptr );
    CHECK( wrapper->getExport( "AAAAA_DoesNotExist" ) == nullptr );
    CHECK( wrapper->getExport( "ZZZZZ_DoesNotExist" ) == nullptr );
}
