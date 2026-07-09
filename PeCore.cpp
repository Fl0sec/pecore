// PeCore.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"
#include "PeFastWrapper.h"

// TODO: This is an example of a library function
void fnPeCore()
{
}

// Compile-time smoke test: exercise the API surface so both x64 and Win32 builds
// catch header/type errors even though nothing here is unit-tested yet.
void PeFastWrapper_CompileSmokeTest( )
{
    if ( auto wrapper = PeFastWrapper::from( GetModuleHandle( nullptr ) ) )
    {
        (void) wrapper->isDLL( );
        (void) wrapper->isEXE( );
        (void) wrapper->isExecutableImage( );
        (void) wrapper->isSystemFile( );
        (void) wrapper->isManagedAssembly( );
        (void) wrapper->getArch( );
        (void) wrapper->hasASLR( );
        (void) wrapper->hasDEP( );
        (void) wrapper->hasCFG( );
        (void) wrapper->isHighEntropyVA( );
        (void) wrapper->getEntryPointRVA( );
        (void) wrapper->getImageBase( );
        (void) wrapper->getSizeOfImage( );
        (void) wrapper->getSubsystem( );
        (void) wrapper->getChecksum( );
        (void) wrapper->getTimestamp( );
        (void) wrapper->getExport( "SomeExport" );
        (void) wrapper->getExport( static_cast<WORD>( 1 ) );

        for ( const auto& descriptor : wrapper->getImportDescriptors( ) )
        {
            (void) wrapper->getImportedModuleName( descriptor );
            (void) wrapper->getImportedFunctions( descriptor );
        }

        (void) wrapper->getRelocations( );
        (void) wrapper->getLoadConfig( );

#if defined( _WIN64 )
        (void) wrapper->getExceptionFunctionTable( );
#endif

        if ( const auto root = wrapper->getResourceRoot( ) )
        {
            for ( const auto& entry : wrapper->getResourceEntries( root ) )
            {
                (void) wrapper->getResourceSubdirectory( entry );
                (void) wrapper->getResourceDataEntry( entry );
            }
        }

        (void) wrapper->getDelayImportDescriptors( );
        (void) wrapper->getBoundImportModules( );
        (void) wrapper->getDebugDirectories( );
        (void) wrapper->getPdb70Info( );
        (void) wrapper->getCor20Header( );

        (void) wrapper->getVmtSection( );
        (void) wrapper->getDataSection( );
        (void) wrapper->getCodeSection( );
        (void) wrapper->getSectionHeaders( );
        (void) wrapper->getSectionContaining( 0x1000 );
        (void) wrapper->getTlsCallbacks( );
        (void) wrapper->getTlsInfo( );
        (void) wrapper->as<HMODULE>( );
        (void) ( *wrapper + 0x10 );
    }
}
