# pecore

[![ci](https://github.com/Fl0sec/pecore/actions/workflows/ci.yml/badge.svg)](https://github.com/Fl0sec/pecore/actions/workflows/ci.yml)

A header-only C++23 library for reading PE32 and PE32+ images that are already
mapped in memory: a module from `LoadLibrary`, `GetModuleHandle`, or any base
address you hold.

It is the parser I reach for in tooling: resolve an export without
`GetProcAddress`, walk imports, find the PDB of a module, list TLS callbacks,
check which mitigations an image was linked with.

```cpp
#include <pecore/PeFastWrapper.h>

if ( const auto pe = PeFastWrapper::from( GetModuleHandleA( "kernel32.dll" ) ) )
{
    FARPROC heapAlloc = pe->getExport( "HeapAlloc" );   // forwarded to ntdll, followed
    bool cfg = pe->hasCFG( );

    for ( const auto& desc : pe->getImportDescriptors( ) )
        for ( const auto& fn : pe->getImportedFunctions( desc ) )
            ; // fn.name, or fn.ordinal when fn.byOrdinal

    if ( const auto pdb = pe->getPdb70Info( ) )
        ; // pdb->guid, pdb->age, pdb->pdbPath
}
```

`from()` checks the DOS signature, `e_lfanew`, the NT signature and the
optional header magic before returning a wrapper. Every lookup after that
returns an empty `optional`, span or `nullptr` instead of throwing.

## What it reads

| Area | API |
|---|---|
| Headers | `getArch`, `isDLL`, `isEXE`, `getImageBase`, `getSizeOfImage`, `getEntryPointRVA`, `getSubsystem`, `getChecksum`, `getTimestamp` |
| Mitigations | `hasASLR`, `hasDEP`, `hasCFG`, `isHighEntropyVA`, `getDllCharacteristics` |
| Exports | `getExport(name)`, `getExport(ordinal)`, optional name hint, forwarders (`module.name` and `module.#ordinal`) |
| Imports | `getImportDescriptors`, `getImportedModuleName`, `getImportedFunctions`, `getDelayImportDescriptors`, `getBoundImportModules` |
| Sections | `getSectionHeaders`, `getSectionContaining(rva)`, `getSectionByName`, `getCodeSection`, `getDataSection` |
| Relocations | `getRelocations` |
| TLS | `getTlsDirectory`, `getTlsCallbacks`, `getTlsInfo` |
| Debug | `getDebugDirectories`, `getPdb70Info` (GUID, age, path) |
| Load config | `getLoadConfig` (32 and 64-bit layouts) |
| Exceptions | `getExceptionFunctionTable` (x64 `.pdata`) |
| Resources | `getResourceRoot`, `getResourceEntries`, `getResourceSubdirectory`, `getResourceDataEntry` |
| .NET | `isManagedAssembly`, `getCor20Header` |

Name lookups use the hint first, then a binary search over `AddressOfNames`,
which the loader keeps sorted. Forwarder chains stop after 16 hops.

## Build

Header only: add `include/` to your include path, or with CMake:

```cmake
add_subdirectory(pecore)
target_link_libraries(your_target PRIVATE pecore::pecore)
```

Tests and the example:

```bash
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

CI builds and tests x64 and Win32, Release and Debug, with MSVC at `/W4 /WX`.

## pedump

`examples/pedump.cpp` loads a module, prints what pecore reads, and checks one
export against `GetProcAddress`:

```text
> pedump kernel32.dll HeapAlloc
kernel32.dll
  arch        x64 DLL
  image base  0x7ffb70610000
  image size  0xc9000
  entry RVA   0x2e120
  mitigations ASLR=1 DEP=1 CFG=1 HighEntropyVA=1

sections
  .text    rva 0x00001000 size 0x00084904
  fothk    rva 0x00086000 size 0x00001000
  .rdata   rva 0x00087000 size 0x00037920
  .data    rva 0x000bf000 size 0x00001668
  ...

getExport("HeapAlloc") = 00007FFB71DFC240, GetProcAddress = 00007FFB71DFC240 -> match
```

## Limits

- Windows only. It uses the `IMAGE_*` types from `<Windows.h>`.
- It reads mapped images, not files on disk: RVAs are used as offsets from the
  base, so a raw file buffer needs mapping first.
- A forwarded export resolves only when the target module is already loaded
  (`GetModuleHandleA`, no `LoadLibrary`).
- `getImportedFunctions`, `getRelocations` and `getBoundImportModules` return a
  `std::vector`. Everything else returns views into the image and allocates
  nothing.

## License

MIT. `tests/doctest.h` is [doctest](https://github.com/doctest/doctest), MIT.
