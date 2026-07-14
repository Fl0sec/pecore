#pragma once
#include <algorithm>
#include <bit>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>
#include <Windows.h>

enum class Architecture : WORD {
	Unknown = IMAGE_FILE_MACHINE_UNKNOWN,
	X86 = IMAGE_FILE_MACHINE_I386,
	X64 = IMAGE_FILE_MACHINE_AMD64,
	Arm = IMAGE_FILE_MACHINE_ARM,
	Arm64 = IMAGE_FILE_MACHINE_ARM64,
};

class PeFastWrapper {

	using OptionalHeaderVariant = std::variant<const IMAGE_OPTIONAL_HEADER32*, const IMAGE_OPTIONAL_HEADER64*>;
	using LoadConfigVariant = std::variant<const IMAGE_LOAD_CONFIG_DIRECTORY32*, const IMAGE_LOAD_CONFIG_DIRECTORY64*>;
	using TlsDirectoryVariant = std::variant<const IMAGE_TLS_DIRECTORY32*, const IMAGE_TLS_DIRECTORY64*>;

	static constexpr int kMaxForwardDepth = 16;
	static constexpr std::size_t kMaxTlsCallbacks = 1024;
	static constexpr LONG kMaxHeaderOffset = 0x1000'0000; // 256 MiB; real e_lfanew is always tiny

public:
	struct ImportedFunction {
		std::string_view name;      // empty when byOrdinal is true
		WORD ordinal { 0 };
		bool byOrdinal { false };
	};

	struct Relocation {
		DWORD rva { 0 };
		WORD type { 0 };            // IMAGE_REL_BASED_*
	};

	struct CvInfoPdb70 {
		GUID guid { };
		DWORD age { 0 };
		std::string_view pdbPath;
	};

	struct BoundImportModule {
		std::string_view name;
		const IMAGE_BOUND_IMPORT_DESCRIPTOR* descriptor { nullptr };
	};

	struct TlsInfo {
		DWORD* addressOfIndex { nullptr };
		std::span<const std::byte> rawData;
	};

public:
	PeFastWrapper ( ) = delete;

	constexpr explicit PeFastWrapper ( const void* base ) noexcept :
		base_ ( static_cast< const std::byte* >( base ) ) { }

	// Validates DOS/NT/optional-header signatures before handing back a usable wrapper.
	[[nodiscard]] static std::optional<PeFastWrapper> from ( const void* base ) noexcept {
		if ( const PeFastWrapper wrapper { base }; wrapper )
			return wrapper;

		return std::nullopt;
	}

public:

	[[nodiscard]] explicit operator bool ( ) const noexcept {
		return getOptionalHeader ( ).has_value ( );
	}

	// --- Classification -----------------------------------------------

	[[nodiscard]] bool isDLL ( ) const noexcept {
		if ( auto ntHeader = getNtHeader ( ) )
		{
			return ntHeader->FileHeader.Characteristics & IMAGE_FILE_DLL;
		}

		return false;
	}

	[[nodiscard]] bool isExecutableImage ( ) const noexcept {
		if ( auto ntHeader = getNtHeader ( ) )
		{
			return ntHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE;
		}

		return false;
	}

	[[nodiscard]] bool isEXE ( ) const noexcept {
		return isExecutableImage ( ) && !isDLL ( );
	}

	[[nodiscard]] bool isSystemFile ( ) const noexcept {
		if ( auto ntHeader = getNtHeader ( ) )
		{
			return ntHeader->FileHeader.Characteristics & IMAGE_FILE_SYSTEM;
		}

		return false;
	}

	[[nodiscard]] bool isManagedAssembly ( ) const noexcept {
		const auto dir = getComDescriptorDataDirectory ( );
		return dir && dir->VirtualAddress != 0;
	}

	[[nodiscard]] Architecture getArch ( ) const noexcept {

		if ( auto ntHeader = getNtHeader ( ) )
		{
			return static_cast< Architecture >( ntHeader->FileHeader.Machine );
		}

		return Architecture::Unknown;
	}

	[[nodiscard]] std::optional<WORD> getDllCharacteristics ( ) const noexcept {
		const auto optHeader = getOptionalHeader ( );
		if ( !optHeader )
			return std::nullopt;

		return std::visit ( [] ( const auto* header ) { return header->DllCharacteristics; }, *optHeader );
	}

	[[nodiscard]] bool hasASLR ( ) const noexcept {
		return getDllCharacteristics ( ).value_or ( 0 ) & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	}

	[[nodiscard]] bool hasDEP ( ) const noexcept {
		return getDllCharacteristics ( ).value_or ( 0 ) & IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	}

	[[nodiscard]] bool hasCFG ( ) const noexcept {
		return getDllCharacteristics ( ).value_or ( 0 ) & IMAGE_DLLCHARACTERISTICS_GUARD_CF;
	}

	[[nodiscard]] bool isHighEntropyVA ( ) const noexcept {
		return getDllCharacteristics ( ).value_or ( 0 ) & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
	}

	// --- Header metadata ------------------------------------------------

	[[nodiscard]] std::optional<DWORD> getEntryPointRVA ( ) const noexcept {

		const auto optHeader = getOptionalHeader ( );
		if ( !optHeader )
			return std::nullopt;

		return std::visit ( [] ( const auto* header ) { return header->AddressOfEntryPoint; }, *optHeader );
	}

	[[nodiscard]] std::optional<std::uint64_t> getImageBase ( ) const noexcept {
		const auto optHeader = getOptionalHeader ( );
		if ( !optHeader )
			return std::nullopt;

		return std::visit ( [] ( const auto* header ) { return static_cast< std::uint64_t >( header->ImageBase ); }, *optHeader );
	}

	[[nodiscard]] std::optional<DWORD> getSizeOfImage ( ) const noexcept {
		const auto optHeader = getOptionalHeader ( );
		if ( !optHeader )
			return std::nullopt;

		return std::visit ( [] ( const auto* header ) { return header->SizeOfImage; }, *optHeader );
	}

	[[nodiscard]] std::optional<WORD> getSubsystem ( ) const noexcept {
		const auto optHeader = getOptionalHeader ( );
		if ( !optHeader )
			return std::nullopt;

		return std::visit ( [] ( const auto* header ) { return header->Subsystem; }, *optHeader );
	}

	[[nodiscard]] std::optional<DWORD> getChecksum ( ) const noexcept {
		const auto optHeader = getOptionalHeader ( );
		if ( !optHeader )
			return std::nullopt;

		return std::visit ( [] ( const auto* header ) { return header->CheckSum; }, *optHeader );
	}

	[[nodiscard]] std::optional<DWORD> getTimestamp ( ) const noexcept {
		if ( auto ntHeader = getNtHeader ( ) )
			return ntHeader->FileHeader.TimeDateStamp;

		return std::nullopt;
	}

	[[nodiscard]] std::uintptr_t operator+( std::ptrdiff_t off ) const noexcept {
		return std::bit_cast< std::uintptr_t >( base_ ) + off;
	}

	template <typename T>
	[[nodiscard]] __forceinline T as ( ) const noexcept requires( std::is_pointer_v<T> || std::is_integral_v<T> ) {
		return std::bit_cast< T >( base_ );
	}

	// --- Exports ----------------------------------------------------------

	template <typename T>
		requires ( std::is_integral_v<T> || std::is_convertible_v<T, const char*> )
	[[nodiscard]] FARPROC getExport ( T identifier, std::optional<WORD> hint = std::nullopt ) const noexcept {
		return getExportImpl ( identifier, hint, 0 );
	}

	// --- Imports ------------------------------------------------------

	[[nodiscard]] std::span<const IMAGE_IMPORT_DESCRIPTOR> getImportDescriptors ( ) const noexcept {

		const auto importDir = getImportDataDirectory ( );
		if ( !importDir || !importDir->VirtualAddress )
			return { };

		const auto descriptors = reinterpret_cast< const IMAGE_IMPORT_DESCRIPTOR* >( base ( ) + importDir->VirtualAddress );

		std::size_t count { 0 };
		while ( descriptors[count].Name != 0 )
			++count;

		return { descriptors, count };
	}

	[[nodiscard]] std::string_view getImportedModuleName ( const IMAGE_IMPORT_DESCRIPTOR& descriptor ) const noexcept {
		if ( !descriptor.Name )
			return { };

		return reinterpret_cast< const char* >( base ( ) + descriptor.Name );
	}

	[[nodiscard]] std::vector<ImportedFunction> getImportedFunctions ( const IMAGE_IMPORT_DESCRIPTOR& descriptor ) const noexcept {
		std::vector<ImportedFunction> result;

		const auto optHeader = getOptionalHeader ( );
		if ( !optHeader )
			return result;

		const DWORD thunkRva = descriptor.OriginalFirstThunk ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
		if ( !thunkRva )
			return result;

		const bool is64 = std::holds_alternative<const IMAGE_OPTIONAL_HEADER64*> ( *optHeader );

		if ( is64 )
		{
			for ( auto thunk = reinterpret_cast< const IMAGE_THUNK_DATA64* >( base ( ) + thunkRva ); thunk->u1.AddressOfData != 0; ++thunk )
			{
				ImportedFunction fn { };

				if ( IMAGE_SNAP_BY_ORDINAL64 ( thunk->u1.Ordinal ) )
				{
					fn.byOrdinal = true;
					fn.ordinal = static_cast< WORD >( IMAGE_ORDINAL64 ( thunk->u1.Ordinal ) );
				}
				else
				{
					const auto importByName = reinterpret_cast< const IMAGE_IMPORT_BY_NAME* >( base ( ) + thunk->u1.AddressOfData );
					fn.name = importByName->Name;
				}

				result.push_back ( fn );
			}
		}
		else
		{
			for ( auto thunk = reinterpret_cast< const IMAGE_THUNK_DATA32* >( base ( ) + thunkRva ); thunk->u1.AddressOfData != 0; ++thunk )
			{
				ImportedFunction fn { };

				if ( IMAGE_SNAP_BY_ORDINAL32 ( thunk->u1.Ordinal ) )
				{
					fn.byOrdinal = true;
					fn.ordinal = static_cast< WORD >( IMAGE_ORDINAL32 ( thunk->u1.Ordinal ) );
				}
				else
				{
					const auto importByName = reinterpret_cast< const IMAGE_IMPORT_BY_NAME* >( base ( ) + thunk->u1.AddressOfData );
					fn.name = importByName->Name;
				}

				result.push_back ( fn );
			}
		}

		return result;
	}

	// --- Base relocations -----------------------------------------------

	[[nodiscard]] std::vector<Relocation> getRelocations ( ) const noexcept {
		std::vector<Relocation> result;

		const auto relocDir = getRelocDataDirectory ( );
		if ( !relocDir || !relocDir->VirtualAddress )
			return result;

		auto block = reinterpret_cast< const IMAGE_BASE_RELOCATION* >( base ( ) + relocDir->VirtualAddress );
		const auto dirEnd = base ( ) + relocDir->VirtualAddress + relocDir->Size;

		while ( reinterpret_cast< const std::byte* >( block ) < dirEnd && block->SizeOfBlock )
		{
			const auto entryCount = ( block->SizeOfBlock - sizeof ( IMAGE_BASE_RELOCATION ) ) / sizeof ( WORD );
			const auto entries = reinterpret_cast< const WORD* >( block + 1 );

			for ( std::size_t i = 0; i < entryCount; ++i )
			{
				const WORD type = entries[i] >> 12;
				const WORD offset = entries[i] & 0xFFF;

				if ( type != IMAGE_REL_BASED_ABSOLUTE )
					result.push_back ( { block->VirtualAddress + offset, type } );
			}

			block = reinterpret_cast< const IMAGE_BASE_RELOCATION* > ( reinterpret_cast< const std::byte* > ( block ) + block->SizeOfBlock );
		}

		return result;
	}

	// --- Data directories -------------------------------------------------

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getExceptionDataDirectory ( ) const noexcept {
		return getDataDirectory ( IMAGE_DIRECTORY_ENTRY_EXCEPTION );
	}

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getTlsDataDirectory ( ) const noexcept {
		return getDataDirectory ( IMAGE_DIRECTORY_ENTRY_TLS );
	}

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getImportDataDirectory ( ) const noexcept {
		return getDataDirectory ( IMAGE_DIRECTORY_ENTRY_IMPORT );
	}

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getExportDataDirectory ( ) const noexcept {
		return getDataDirectory ( IMAGE_DIRECTORY_ENTRY_EXPORT );
	}

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getRelocDataDirectory ( ) const noexcept {
		return getDataDirectory ( IMAGE_DIRECTORY_ENTRY_BASERELOC );
	}

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getResourceDataDirectory ( ) const noexcept {
		return getDataDirectory ( IMAGE_DIRECTORY_ENTRY_RESOURCE );
	}

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getDebugDataDirectory ( ) const noexcept {
		return getDataDirectory ( IMAGE_DIRECTORY_ENTRY_DEBUG );
	}

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getLoadConfigDataDirectory ( ) const noexcept {
		return getDataDirectory ( IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG );
	}

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getBoundImportDataDirectory ( ) const noexcept {
		return getDataDirectory ( IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT );
	}

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getDelayImportDataDirectory ( ) const noexcept {
		return getDataDirectory ( IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT );
	}

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getComDescriptorDataDirectory ( ) const noexcept {
		return getDataDirectory ( IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR );
	}

	[[nodiscard]] const IMAGE_DATA_DIRECTORY* getDataDirectory ( std::uint8_t entry ) const noexcept {

		const auto optHeader = getOptionalHeader ( );
		if ( !optHeader )
			return nullptr;

		return std::visit ( [entry] ( const auto* header ) -> const IMAGE_DATA_DIRECTORY* {
			return header->NumberOfRvaAndSizes > entry ? &header->DataDirectory[entry] : nullptr;
		}, *optHeader );
	}

	// Magic is at the same offset/size in IMAGE_OPTIONAL_HEADER32 and 64, so this
	// dispatches to the layout the image actually declares, independent of host bitness.
	[[nodiscard]] std::optional<OptionalHeaderVariant> getOptionalHeader ( ) const noexcept {

		const auto ntHeader = getNtHeader ( );
		if ( !ntHeader )
			return std::nullopt;

		const auto optHeader = &ntHeader->OptionalHeader;

		switch ( optHeader->Magic )
		{
			case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
				return OptionalHeaderVariant { reinterpret_cast< const IMAGE_OPTIONAL_HEADER32* >( optHeader ) };
			case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
				return OptionalHeaderVariant { optHeader };
			default:
				return std::nullopt;
		}
	}

	// Same 32/64 dispatch idea as getOptionalHeader(), driven by the same Magic value
	// rather than re-deriving bitness independently.
	[[nodiscard]] std::optional<LoadConfigVariant> getLoadConfig ( ) const noexcept {

		const auto dir = getLoadConfigDataDirectory ( );
		const auto optHeader = getOptionalHeader ( );
		if ( !dir || !dir->VirtualAddress || !optHeader )
			return std::nullopt;

		const auto raw = base ( ) + dir->VirtualAddress;

		if ( std::holds_alternative<const IMAGE_OPTIONAL_HEADER64*> ( *optHeader ) )
			return LoadConfigVariant { reinterpret_cast< const IMAGE_LOAD_CONFIG_DIRECTORY64* >( raw ) };

		return LoadConfigVariant { reinterpret_cast< const IMAGE_LOAD_CONFIG_DIRECTORY32* >( raw ) };
	}

	// --- Exception directory (x64/ARM64 table-based unwind info only) ----

#if defined( _WIN64 )
	[[nodiscard]] std::span<const RUNTIME_FUNCTION> getExceptionFunctionTable ( ) const noexcept {

		const auto exceptionDir = getExceptionDataDirectory ( );
		if ( !exceptionDir || !exceptionDir->VirtualAddress )
			return { };

		const auto functions = reinterpret_cast< const RUNTIME_FUNCTION* >( base ( ) + exceptionDir->VirtualAddress );
		const auto count = exceptionDir->Size / sizeof ( RUNTIME_FUNCTION );

		return { functions, count };
	}
#endif

	// --- Resources ---------------------------------------------------

	[[nodiscard]] const IMAGE_RESOURCE_DIRECTORY* getResourceRoot ( ) const noexcept {

		const auto dir = getResourceDataDirectory ( );
		if ( !dir || !dir->VirtualAddress )
			return nullptr;

		return reinterpret_cast< const IMAGE_RESOURCE_DIRECTORY* >( base ( ) + dir->VirtualAddress );
	}

	[[nodiscard]] std::span<const IMAGE_RESOURCE_DIRECTORY_ENTRY> getResourceEntries ( const IMAGE_RESOURCE_DIRECTORY* directory ) const noexcept {

		if ( !directory )
			return { };

		const auto entries = reinterpret_cast< const IMAGE_RESOURCE_DIRECTORY_ENTRY* >( directory + 1 );
		return { entries, static_cast< std::size_t >( directory->NumberOfNamedEntries ) + directory->NumberOfIdEntries };
	}

	[[nodiscard]] const IMAGE_RESOURCE_DIRECTORY* getResourceSubdirectory ( const IMAGE_RESOURCE_DIRECTORY_ENTRY& entry ) const noexcept {

		const auto dir = getResourceDataDirectory ( );
		if ( !dir || !entry.DataIsDirectory )
			return nullptr;

		return reinterpret_cast< const IMAGE_RESOURCE_DIRECTORY* >( base ( ) + dir->VirtualAddress + entry.OffsetToDirectory );
	}

	[[nodiscard]] const IMAGE_RESOURCE_DATA_ENTRY* getResourceDataEntry ( const IMAGE_RESOURCE_DIRECTORY_ENTRY& entry ) const noexcept {

		const auto dir = getResourceDataDirectory ( );
		if ( !dir || entry.DataIsDirectory )
			return nullptr;

		return reinterpret_cast< const IMAGE_RESOURCE_DATA_ENTRY* >( base ( ) + dir->VirtualAddress + entry.OffsetToData );
	}

	// --- Delay-load imports -----------------------------------------------

	[[nodiscard]] std::span<const IMAGE_DELAYLOAD_DESCRIPTOR> getDelayImportDescriptors ( ) const noexcept {

		const auto dir = getDelayImportDataDirectory ( );
		if ( !dir || !dir->VirtualAddress )
			return { };

		const auto descriptors = reinterpret_cast< const IMAGE_DELAYLOAD_DESCRIPTOR* >( base ( ) + dir->VirtualAddress );

		std::size_t count { 0 };
		while ( descriptors[count].DllNameRVA != 0 )
			++count;

		return { descriptors, count };
	}

	// --- Bound imports -------------------------------------------------

	[[nodiscard]] std::vector<BoundImportModule> getBoundImportModules ( ) const noexcept {
		std::vector<BoundImportModule> result;

		const auto dir = getBoundImportDataDirectory ( );
		if ( !dir || !dir->VirtualAddress )
			return result;

		const auto directoryStart = base ( ) + dir->VirtualAddress;
		auto descriptor = reinterpret_cast< const IMAGE_BOUND_IMPORT_DESCRIPTOR* >( directoryStart );

		while ( descriptor->OffsetModuleName != 0 )
		{
			const auto name = reinterpret_cast< const char* >( directoryStart + descriptor->OffsetModuleName );
			result.push_back ( { name, descriptor } );

			// Each descriptor is followed by NumberOfModuleForwarderRefs IMAGE_BOUND_FORWARDER_REF
			// entries, so the stride to the next descriptor is variable.
			descriptor = reinterpret_cast< const IMAGE_BOUND_IMPORT_DESCRIPTOR* >(
				reinterpret_cast< const IMAGE_BOUND_FORWARDER_REF* >( descriptor + 1 ) + descriptor->NumberOfModuleForwarderRefs );
		}

		return result;
	}

	// --- Debug directory ------------------------------------------------

	[[nodiscard]] std::span<const IMAGE_DEBUG_DIRECTORY> getDebugDirectories ( ) const noexcept {

		const auto dir = getDebugDataDirectory ( );
		if ( !dir || !dir->VirtualAddress )
			return { };

		const auto entries = reinterpret_cast< const IMAGE_DEBUG_DIRECTORY* >( base ( ) + dir->VirtualAddress );
		const auto count = dir->Size / sizeof ( IMAGE_DEBUG_DIRECTORY );

		return { entries, count };
	}

	// Finds the CodeView entry and decodes it as the "RSDS"/PDB70 record (the format
	// every modern toolchain emits); the older NB10 CodeView format is not handled.
	[[nodiscard]] std::optional<CvInfoPdb70> getPdb70Info ( ) const noexcept {

		for ( const auto& entry : getDebugDirectories ( ) )
		{
			if ( entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || !entry.AddressOfRawData )
				continue;

			struct RawCvInfoPdb70 {
				DWORD CvSignature;
				GUID Signature;
				DWORD Age;
				char PdbFileName[1];
			};

			const auto cv = reinterpret_cast< const RawCvInfoPdb70* >( base ( ) + entry.AddressOfRawData );

			if ( std::memcmp ( &cv->CvSignature, "RSDS", sizeof ( cv->CvSignature ) ) != 0 )
				continue;

			return CvInfoPdb70 { cv->Signature, cv->Age, cv->PdbFileName };
		}

		return std::nullopt;
	}

	// --- COM / .NET ---------------------------------------------------

	[[nodiscard]] const IMAGE_COR20_HEADER* getCor20Header ( ) const noexcept {

		const auto dir = getComDescriptorDataDirectory ( );
		if ( !dir || !dir->VirtualAddress )
			return nullptr;

		return reinterpret_cast< const IMAGE_COR20_HEADER* >( base ( ) + dir->VirtualAddress );
	}

	// --- Sections -------------------------------------------------------

	[[nodiscard]] std::span<const std::byte> getSectionByName ( const std::string_view name, DWORD flags = IMAGE_SCN_MEM_READ ) const noexcept {

		if ( name.empty ( ) || name.length ( ) > IMAGE_SIZEOF_SHORT_NAME )
			return {};

		const auto imageSize = getSizeOfImage ( );
		if ( !imageSize )
			return {};

		for ( const auto& section : getSectionHeaders ( ) )
		{
			if ( flags != 0 && !( section.Characteristics & flags ) )
				continue;

			// Name is a fixed 8-byte field, not necessarily null-terminated when exactly
			// 8 chars long -- compare the trimmed full field so a search for ".tex" can't
			// false-match ".text".
			const std::string_view sectionName { reinterpret_cast< const char* >( section.Name ), IMAGE_SIZEOF_SHORT_NAME };

			if ( sectionName.substr ( 0, sectionName.find ( '\0' ) ) != name || section.VirtualAddress >= *imageSize )
				continue;

			const auto remaining = static_cast< std::size_t >( *imageSize - section.VirtualAddress );
			const auto sectionSize = std::min< std::size_t >( section.Misc.VirtualSize, remaining );
			return { base ( ) + section.VirtualAddress, sectionSize };
		}

		return {};
	}

	[[nodiscard]] std::span<const std::byte> getVmtSection ( ) const noexcept {
		return getSectionByName ( ".rdata" );
	}

	[[nodiscard]] std::span<const std::byte> getDataSection ( ) const noexcept {
		return getSectionByName ( ".data" );
	}

	[[nodiscard]] std::span<const std::byte> getCodeSection ( ) const noexcept {
		return getSectionByName ( ".text", IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE );
	}

	[[nodiscard]] std::span<const IMAGE_SECTION_HEADER> getSectionHeaders ( ) const noexcept {

		if ( auto ntHeader = getNtHeader ( ) )
		{
			return {
				reinterpret_cast< const IMAGE_SECTION_HEADER* >(
					reinterpret_cast< const std::byte* >( &ntHeader->OptionalHeader ) + ntHeader->FileHeader.SizeOfOptionalHeader ),
				ntHeader->FileHeader.NumberOfSections
			};
		}

		return { };
	}

	[[nodiscard]] const IMAGE_SECTION_HEADER* getSectionContaining ( DWORD rva ) const noexcept {
		const auto imageSize = getSizeOfImage ( );
		if ( !imageSize || rva >= *imageSize )
			return nullptr;

		for ( const auto& section : getSectionHeaders ( ) )
		{
			if ( section.VirtualAddress >= *imageSize )
				continue;

			const auto remaining = static_cast< std::size_t >( *imageSize - section.VirtualAddress );
			const auto sectionSize = std::min< std::size_t >( section.Misc.VirtualSize, remaining );
			if ( rva >= section.VirtualAddress && static_cast< std::size_t >( rva - section.VirtualAddress ) < sectionSize )
				return &section;
		}

		return nullptr;
	}

	// --- TLS -----------------------------------------------------------

	// Same 32/64 dispatch idea as getOptionalHeader()/getLoadConfig(), driven by the
	// image's own Magic value rather than the host build's bitness.
	[[nodiscard]] std::optional<TlsDirectoryVariant> getTlsDirectory ( ) const noexcept {

		const auto dir = getTlsDataDirectory ( );
		const auto optHeader = getOptionalHeader ( );
		if ( !dir || !dir->VirtualAddress || !optHeader )
			return std::nullopt;

		const auto raw = base ( ) + dir->VirtualAddress;

		if ( std::holds_alternative<const IMAGE_OPTIONAL_HEADER64*> ( *optHeader ) )
			return TlsDirectoryVariant { reinterpret_cast< const IMAGE_TLS_DIRECTORY64* >( raw ) };

		return TlsDirectoryVariant { reinterpret_cast< const IMAGE_TLS_DIRECTORY32* >( raw ) };
	}

	// AddressOfCallBacks is an absolute VA, valid only for an already-relocated, loaded
	// module in the current process -- which means its width always matches this
	// process's native pointer width once the correct (32 vs 64) TLS layout is selected
	// above, since a 32-bit image can only be loaded into a 32-bit (WOW64) process and
	// vice versa. The sizeof check below is a belt-and-suspenders guard against that
	// invariant somehow not holding (e.g. a hand-crafted buffer), not the expected path.
	[[nodiscard]] std::span<PIMAGE_TLS_CALLBACK> getTlsCallbacks ( ) const noexcept {

		const auto tls = getTlsDirectory ( );
		if ( !tls )
			return { };

		return std::visit ( [] ( const auto* dir ) -> std::span<PIMAGE_TLS_CALLBACK> {

			using VaT = std::remove_cvref_t<decltype( dir->AddressOfCallBacks )>;

			if constexpr ( sizeof ( VaT ) != sizeof ( PIMAGE_TLS_CALLBACK* ) )
			{
				return { };
			}
			else
			{
				if ( !dir->AddressOfCallBacks )
					return { };

				auto tlsCallbacks = std::bit_cast< PIMAGE_TLS_CALLBACK* >( dir->AddressOfCallBacks );

				std::size_t count { 0 };

				while ( tlsCallbacks[count] != nullptr && count < kMaxTlsCallbacks )
					++count;

				return { tlsCallbacks, count };
			}
		}, *tls );
	}

	// AddressOfIndex/StartAddressOfRawData/EndAddressOfRawData are absolute VAs
	// (as with AddressOfCallBacks above) — same same-process/same-bitness precondition applies.
	[[nodiscard]] std::optional<TlsInfo> getTlsInfo ( ) const noexcept {

		const auto tls = getTlsDirectory ( );
		if ( !tls )
			return std::nullopt;

		return std::visit ( [] ( const auto* dir ) -> std::optional<TlsInfo> {

			using VaT = std::remove_cvref_t<decltype( dir->AddressOfIndex )>;

			if constexpr ( sizeof ( VaT ) != sizeof ( void* ) )
			{
				return std::nullopt;
			}
			else
			{
				TlsInfo info { };
				info.addressOfIndex = std::bit_cast< DWORD* >( dir->AddressOfIndex );

				if ( dir->StartAddressOfRawData && dir->EndAddressOfRawData >= dir->StartAddressOfRawData )
				{
					info.rawData = {
						std::bit_cast< const std::byte* >( dir->StartAddressOfRawData ),
						static_cast< std::size_t >( dir->EndAddressOfRawData - dir->StartAddressOfRawData )
					};
				}

				return info;
			}
		}, *tls );
	}

private:

	template <typename T>
		requires ( std::is_integral_v<T> || std::is_convertible_v<T, const char*> )
	[[nodiscard]] FARPROC getExportImpl ( T identifier, std::optional<WORD> hint, int depth ) const noexcept {

		if ( depth > kMaxForwardDepth )
			return nullptr;

		const auto exportDataDir = getExportDataDirectory ( );
		if ( !exportDataDir )
			return nullptr;

		const auto exportDirectory = reinterpret_cast< const IMAGE_EXPORT_DIRECTORY* >( base ( ) + exportDataDir->VirtualAddress );
		const auto functions = reinterpret_cast< const DWORD* >( base ( ) + exportDirectory->AddressOfFunctions );
		DWORD functionRVA {};

		if constexpr ( std::is_integral_v<T> )
		{ // Ordinal branch

			const auto ordinalBase = exportDirectory->Base;
			const auto index = static_cast< DWORD >( identifier ) - ordinalBase;

			if ( index < exportDirectory->NumberOfFunctions )
				functionRVA = functions[index];


		}
		else if constexpr ( std::is_convertible_v<T, const char*> )
		{ // Name branch

			const auto names = reinterpret_cast< const DWORD* > ( base ( ) + exportDirectory->AddressOfNames );
			const auto nameOrdinals = reinterpret_cast< const WORD* > ( base ( ) + exportDirectory->AddressOfNameOrdinals );


			// Fast path: try hint
			if ( hint.has_value ( ) && *hint < exportDirectory->NumberOfNames )
			{
				const char* nameAtHint = reinterpret_cast< const char* > ( base ( ) + names[*hint] );

				if ( std::strcmp ( nameAtHint, identifier ) == 0 )
				{
					functionRVA = functions[nameOrdinals[*hint]];
				}
			}

			// AddressOfNames is documented (and relied on by the real loader's
			// GetProcAddress) to be sorted ascending by name -- binary search instead
			// of a linear scan over what can be thousands of entries on large DLLs.
			if ( !functionRVA )
			{
				DWORD low = 0;
				DWORD high = exportDirectory->NumberOfNames;

				while ( low < high )
				{
					const DWORD mid = low + ( high - low ) / 2;
					const auto candidateName = reinterpret_cast< const char* > ( base ( ) + names[mid] );
					const int cmp = std::strcmp( candidateName, identifier );

					if ( cmp == 0 )
					{
						functionRVA = functions[nameOrdinals[mid]];
						break;
					}
					else if ( cmp < 0 )
					{
						low = mid + 1;
					}
					else
					{
						high = mid;
					}
				}
			}
		}
		if ( functionRVA )
		{
			if ( isForwardedExport ( functionRVA, *exportDataDir ) )
			{
				const auto exportedName = reinterpret_cast< const char* >( base ( ) + functionRVA );

				return getForwardedExport ( exportedName, depth + 1 );

			}
			else
			{
				return reinterpret_cast< FARPROC >( base ( ) + functionRVA );
			}
		}


		return nullptr;
	}

	// fwdName is a view into the export directory's own null-terminated "module.function"
	// string, so fnInfo below (a suffix of it) is still safely usable as a C-string via
	// .data() -- no copy is needed to isolate it. Only the module-name portion needs its
	// own null terminator (for GetModuleHandleA), which a small stack buffer covers
	// without heap allocation -- important since bad_alloc from a std::string copy would
	// otherwise std::terminate this noexcept call chain.
	[[nodiscard]] FARPROC getForwardedExport ( std::string_view fwdName, int depth ) const noexcept {

		const auto separatorPos = fwdName.find ( '.' );

		// should exist and not be at the end
		if ( separatorPos == std::string_view::npos || separatorPos + 1 >= fwdName.size ( ) )
			return nullptr;

		const auto moduleName = fwdName.substr ( 0, separatorPos );
		const auto fnInfo = fwdName.substr ( separatorPos + 1 );

		if ( moduleName.size ( ) >= MAX_PATH )
			return nullptr;

		char moduleNameBuffer[MAX_PATH];
		std::memcpy ( moduleNameBuffer, moduleName.data ( ), moduleName.size ( ) );
		moduleNameBuffer[moduleName.size ( )] = '\0';

		// Explicit -A form: fwdName is always narrow, regardless of the project's
		// UNICODE/CharacterSet setting (plain GetModuleHandle would resolve to
		// GetModuleHandleW and fail to compile against a char* argument).
		const auto mod = GetModuleHandleA ( moduleNameBuffer );

		if ( !mod )
			return nullptr;

		const PeFastWrapper target { mod };

		// handle if ordinal or string
		if ( fnInfo[0] != '#' ) // by name
		{
			return target.getExportImpl ( fnInfo.data ( ), std::nullopt, depth );
		}
		else // ordinal
		{
			if ( fnInfo.size ( ) < 2 )
				return nullptr;

			int ordinal { };
			const auto result = std::from_chars ( fnInfo.data ( ) + 1, fnInfo.data ( ) + fnInfo.size ( ), ordinal );

			if ( result.ec != std::errc { } || ordinal < 0 || ordinal > 0xFFFF )
				return nullptr;

			return target.getExportImpl ( static_cast< WORD >( ordinal ), std::nullopt, depth );
		}
	}

	[[nodiscard]] __forceinline bool isForwardedExport ( DWORD functionRva, const IMAGE_DATA_DIRECTORY& exportDataDirectory ) const noexcept {

		return functionRva >= exportDataDirectory.VirtualAddress && functionRva - exportDataDirectory.VirtualAddress < exportDataDirectory.Size; // Is functionRva within the export directory memory range ?

	}

	[[nodiscard]] __forceinline const IMAGE_NT_HEADERS64* getNtHeader ( ) const noexcept {

		if ( auto dosHeader = getDosHeader ( ) )
		{
			// Reject an obviously corrupt/adversarial e_lfanew before dereferencing through
			// it. This is a sanity cap, not a real bounds check -- the class tracks no
			// mapped-image size, so a fully rigorous check against the real image extent
			// isn't possible without adding one.
			if ( dosHeader->e_lfanew <= 0 || dosHeader->e_lfanew > kMaxHeaderOffset )
				return nullptr;

			const auto ntHeader = reinterpret_cast< const IMAGE_NT_HEADERS64* >( base ( ) + dosHeader->e_lfanew );

			return ntHeader->Signature == IMAGE_NT_SIGNATURE ? ntHeader : nullptr;
		}

		return nullptr;

	}

	[[nodiscard]] __forceinline const IMAGE_DOS_HEADER* getDosHeader ( ) const noexcept {

		if ( !base_ )
			return nullptr;

		const auto dosHeader = reinterpret_cast< const IMAGE_DOS_HEADER* >( base_ );

		return dosHeader->e_magic == IMAGE_DOS_SIGNATURE ? dosHeader : nullptr;
	}

	[[nodiscard]] __forceinline const std::byte* base ( ) const noexcept {
		return base_;
	}

private:
	const std::byte* base_;
};
