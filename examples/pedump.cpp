// pedump: load a module and print what pecore reads from its in-memory image.
//   pedump [module]      (default: ntdll.dll)

#include <pecore/PeFastWrapper.h>

#include <cstdio>

namespace {

    const char* archName( Architecture arch ) {
        switch ( arch )
        {
        case Architecture::X86:   return "x86";
        case Architecture::X64:   return "x64";
        case Architecture::Arm:   return "ARM";
        case Architecture::Arm64: return "ARM64";
        default:                  return "unknown";
        }
    }

}

int main( int argc, char** argv ) {
    const char* moduleName = argc > 1 ? argv[1] : "ntdll.dll";

    const HMODULE module = LoadLibraryA( moduleName );
    if ( !module )
    {
        std::fprintf( stderr, "cannot load %s (error %lu)\n", moduleName, GetLastError( ) );
        return 1;
    }

    const auto pe = PeFastWrapper::from( module );
    if ( !pe )
    {
        std::fprintf( stderr, "%s: not a valid PE image\n", moduleName );
        return 1;
    }

    std::printf( "%s\n", moduleName );
    std::printf( "  arch        %s %s\n", archName( pe->getArch( ) ), pe->isDLL( ) ? "DLL" : "EXE" );
    std::printf( "  image base  0x%llx\n", static_cast<unsigned long long>( pe->getImageBase( ).value_or( 0 ) ) );
    std::printf( "  image size  0x%lx\n", pe->getSizeOfImage( ).value_or( 0 ) );
    std::printf( "  entry RVA   0x%lx\n", pe->getEntryPointRVA( ).value_or( 0 ) );
    std::printf( "  mitigations ASLR=%d DEP=%d CFG=%d HighEntropyVA=%d\n",
                 pe->hasASLR( ), pe->hasDEP( ), pe->hasCFG( ), pe->isHighEntropyVA( ) );

    std::printf( "\nsections\n" );
    for ( const auto& section : pe->getSectionHeaders( ) )
        std::printf( "  %-8.8s rva 0x%08lx size 0x%08lx\n",
                     reinterpret_cast<const char*>( section.Name ), section.VirtualAddress, section.Misc.VirtualSize );

    std::printf( "\nimports\n" );
    for ( const auto& descriptor : pe->getImportDescriptors( ) )
    {
        const auto name = pe->getImportedModuleName( descriptor );
        std::printf( "  %-48.*s %zu functions\n", static_cast<int>( name.size( ) ), name.data( ),
                     pe->getImportedFunctions( descriptor ).size( ) );
    }

    if ( const auto pdb = pe->getPdb70Info( ) )
        std::printf( "\npdb  %.*s (age %lu)\n", static_cast<int>( pdb->pdbPath.size( ) ), pdb->pdbPath.data( ), pdb->age );

    std::printf( "relocations  %zu\n", pe->getRelocations( ).size( ) );
    std::printf( "TLS callbacks %zu\n", pe->getTlsCallbacks( ).size( ) );

    // Cross-check one export against the loader.
    const char* probe = argc > 2 ? argv[2] : "RtlGetVersion";
    const FARPROC ours = pe->getExport( probe );
    const FARPROC loader = GetProcAddress( module, probe );
    std::printf( "\ngetExport(\"%s\") = %p, GetProcAddress = %p -> %s\n", probe,
                 reinterpret_cast<void*>( ours ), reinterpret_cast<void*>( loader ), ours == loader ? "match" : "MISMATCH" );

    return ours == loader ? 0 : 2;
}
