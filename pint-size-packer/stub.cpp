#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "strings.h"
#include "pe.h"
#include "miniz-2.1.0/miniz.h"

#define NtCurrentProcess (HANDLE)-1
#define ImageBaseAddress NtCurrentTeb()->ProcessEnvironmentBlock->Reserved3[1]
#define STUB_DATA __declspec( allocate( ".stub" ) )
#pragma code_seg( push, ".stub" )

//
// Function Definitions
//
typedef NTSTATUS( NTAPI* NtAllocateVirtualMemory_t )( HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect );
typedef NTSTATUS( NTAPI* NtFreeVirtualMemory_t )( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType );
typedef NTSTATUS( NTAPI* NtProtectVirtualMemory_t )( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewProtect, PULONG OldProtect );
typedef void*( WINAPI* GetProcAddress_t )( void* hModule, char* apiname );
typedef void*( WINAPI* LoadLibraryA_t )( char* lib );

//
// Globals
//
STUB_DATA size_t ImageBase;
STUB_DATA uint32_t OriginalEntryPoint;
STUB_DATA uint32_t NumberOfSections;
STUB_DATA DECLSPEC_ALIGN( 16 ) IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
STUB_DATA DECLSPEC_ALIGN( 16 ) IMAGE_SECTION_HEADER SectionHeaders[16];

//
// Function Pointer Declarations
//
STUB_DATA GetProcAddress_t pGetProcAddress;
STUB_DATA LoadLibraryA_t pLoadLibraryA;
STUB_DATA NtFreeVirtualMemory_t pNtFreeVirtualMemory;
STUB_DATA NtAllocateVirtualMemory_t pNtAllocateVirtualMemory;
STUB_DATA NtProtectVirtualMemory_t pNtProtectVirtualMemory;

//
// Module declarations
//
STUB_DATA void* pKernel32;
STUB_DATA void* pNtdll;

//
// String declarations
//
STUB_DATA wchar_t wcKernel32[] = L"kernel32.dll";
STUB_DATA wchar_t wcNtdll[] = L"ntdll.dll";
STUB_DATA char sGetProcAddress[] = "GetProcAddress";
STUB_DATA char sLoadLibraryA[] = "LoadLibraryA";
STUB_DATA char sNtFreeVirtualMemory[] = "NtFreeVirtualMemory";
STUB_DATA char sNtAllocateVirtualMemory[] = "NtAllocateVirtualMemory";
STUB_DATA char sNtProtectVirtualMemory[] = "NtProtectVirtualMemory";
STUB_DATA char sSectionNameRsrc[] = ".rsrc";



#pragma check_stack( off )
DECLSPEC_SAFEBUFFERS DECLSPEC_NOINLINE void* get_module_handle( const wchar_t* name )
{
    if ( name == nullptr ) {
        return ImageBaseAddress;
    }

    PLIST_ENTRY head = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY cur = head->Flink;

    while ( cur != head ) {

        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD( cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
        wchar_t* mname = stub_strrchr( entry->FullDllName.Buffer, L'\\' );

        if ( stub_stricmp( name, ++mname ) == 0 ) {
            return entry->DllBase;
        }

        cur = cur->Flink;

    }

    return nullptr;
}



#pragma check_stack( off )
DECLSPEC_SAFEBUFFERS DECLSPEC_NOINLINE void* get_proc_address( void* hModule, char* apiname )
{
    PEHeader pe( hModule );

    PIMAGE_DATA_DIRECTORY export_data_dir = pe.data_dir( IMAGE_DIRECTORY_ENTRY_EXPORT );
    PIMAGE_EXPORT_DIRECTORY export_dir = ( PIMAGE_EXPORT_DIRECTORY )pe.rva2va( export_data_dir->VirtualAddress );

    PDWORD names = (PDWORD)pe.rva2va( export_dir->AddressOfNames );
    PDWORD functions = (PDWORD)pe.rva2va( export_dir->AddressOfFunctions );
    PWORD ordinals = (PWORD)pe.rva2va( export_dir->AddressOfNameOrdinals );

    for ( UINT64 i = 0; i < export_dir->NumberOfNames; i++ ) {

        char* fname = (char*)pe.rva2va( names[i] );

        if ( stub_stricmp( fname, apiname ) == 0 ) {

            UINT64 index = *( ordinals + i );
            UINT64 offset = *( functions + index );

            return pe.rva2va( offset );
        }
    }

    return nullptr;
}



#pragma check_stack( off )
#pragma strict_gs_check( off )
DECLSPEC_SAFEBUFFERS DECLSPEC_NOINLINE static void stub_init( void )
{
    pKernel32 = get_module_handle( wcKernel32 );
    pNtdll = get_module_handle( wcNtdll );

    _ReadWriteBarrier();

    pGetProcAddress = (GetProcAddress_t)get_proc_address( pKernel32, sGetProcAddress );
    pLoadLibraryA = (LoadLibraryA_t)get_proc_address( pKernel32, sLoadLibraryA );
    pNtFreeVirtualMemory = (NtFreeVirtualMemory_t)get_proc_address( pNtdll, sNtFreeVirtualMemory );
    pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)get_proc_address( pNtdll, sNtAllocateVirtualMemory );
    pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)get_proc_address( pNtdll, sNtProtectVirtualMemory );



    _ReadWriteBarrier();
}

DECLSPEC_NOINLINE void* stub_memcpy_reverse( void* dst, const void* src, uint32_t n )
{
    unsigned char* d = (unsigned char*)dst;
    unsigned char* s = (unsigned char*)src;

    // LOL idk why but when I inline this function and use while( --n >= 0 ) the compiled generated an infinite loop
    for ( int i = n - 1; i >= 0; i-- ) {
        d[i] = s[i];
    }

    return dst;
}


DECLSPEC_SAFEBUFFERS DECLSPEC_NOINLINE static void decompress_sections( void )
{
    PEHeader pe( get_module_handle( 0 ) );

    uint8_t* base = (uint8_t*)pe.get_base();

    for ( int i = NumberOfSections - 1; i > 0; i-- ) {
        PIMAGE_SECTION_HEADER hdr = &SectionHeaders[i];
        volatile uint32_t size = hdr->SizeOfRawData;
        stub_memcpy_reverse( &base[hdr->VirtualAddress], &base[SectionHeaders[0].VirtualAddress + hdr->PointerToRawData - SectionHeaders[0].PointerToRawData], size );
    }

#if 0
    for ( int i = 0; i < pe.file_hdr()->NumberOfSections; i++ ) {
    
        PIMAGE_SECTION_HEADER section = pe.section_hdr( i );
        if ( section->PointerToLinenumbers == 0 ) {
            continue;
        }
        
        uint8_t* pCmp = (uint8_t*)pe.rva2va( section->VirtualAddress );
        uint8_t* pUncomp = nullptr;
        size_t uncomp_len = section->PointerToLinenumbers;
        mz_ulong cmp_len = section->SizeOfRawData;

        pNtAllocateVirtualMemory( NtCurrentProcess, (void**)&pUncomp, NULL, &uncomp_len, MEM_COMMIT, PAGE_READWRITE );

        uncompress( pUncomp, (mz_ulong*)&uncomp_len, pCmp, cmp_len );
        
        stub_memcpy( pCmp, pUncomp, uncomp_len );

        pNtFreeVirtualMemory( NtCurrentProcess, (void**)&pUncomp, &uncomp_len, MEM_RELEASE );

    }
#endif

}



#pragma check_stack( off )
DECLSPEC_SAFEBUFFERS DECLSPEC_NOINLINE static void fix_import_dir( PEHeader& pe )
{
    if ( DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 ) {
        return;
    }

    PIMAGE_DATA_DIRECTORY dir_iat = &DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    size_t iat_size = dir_iat->Size;
    void* iat_addr = pe.rva2va( dir_iat->VirtualAddress );
    DWORD prot;
    pNtProtectVirtualMemory( NtCurrentProcess, &iat_addr, &iat_size, PAGE_READWRITE, &prot );

    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)pe.rva2va( DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );

    while ( import_desc->Name ) {
    
        void* hModule = pLoadLibraryA( (char*)pe.rva2va( import_desc->Name ) );

        PIMAGE_THUNK_DATA lookup = (PIMAGE_THUNK_DATA)pe.rva2va( import_desc->OriginalFirstThunk );
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)pe.rva2va( import_desc->FirstThunk );

        while ( lookup->u1.AddressOfData ) {

            if ( IMAGE_SNAP_BY_ORDINAL( lookup->u1.Ordinal ) ) {

                iat->u1.Function = (uint64_t)pGetProcAddress( hModule, (char*)pe.rva2va( IMAGE_ORDINAL( lookup->u1.AddressOfData ) ) );
            
            } else {

                char* name = (char*)( (PIMAGE_IMPORT_BY_NAME)pe.rva2va( lookup->u1.AddressOfData ) )->Name;
                iat->u1.Function = (uint64_t)pGetProcAddress( hModule, name );

            }

            lookup++;
            iat++;
        }

        import_desc++;
    
    }


    
    pNtProtectVirtualMemory( NtCurrentProcess, &iat_addr, &iat_size, prot, &prot );
}


DECLSPEC_SAFEBUFFERS DECLSPEC_NOINLINE static void fix_reloc_dir( PEHeader& pe )
{
    PIMAGE_DATA_DIRECTORY reloc_dir = &DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if ( reloc_dir->Size == 0 ) {
        return;
    }

    size_t delta = ( (uintptr_t)pe.get_base() - ImageBase );
    PIMAGE_BASE_RELOCATION reloc_table = (PIMAGE_BASE_RELOCATION)pe.rva2va( reloc_dir->VirtualAddress );
    void* table_end = (char*)reloc_table + reloc_dir->Size;

    while ( reloc_table < table_end && reloc_table->SizeOfBlock ) {
        struct _Reloc {
            WORD Offset : 12;
            WORD Type : 4;
        }* reloc = (_Reloc*)( reloc_table + 1 );

        DWORD count = ( reloc_table->SizeOfBlock - sizeof( *reloc_table ) ) / sizeof( WORD );

        for ( DWORD i = 0; i < count; i++ ) {
            uintptr_t* va = (uintptr_t*)( (uintptr_t)pe.rva2va( reloc_table->VirtualAddress ) + reloc[i].Offset );
            switch ( reloc[i].Type ) {
                case IMAGE_REL_BASED_HIGH:
                    *va += HIWORD( delta );
                    break;
                case IMAGE_REL_BASED_LOW:
                    *va += LOWORD( delta );
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *va += delta;
                    break;
                case IMAGE_REL_BASED_DIR64:
                    *va += delta;
                    break;
            }
        }

        reloc_table = ( PIMAGE_BASE_RELOCATION )( (uintptr_t)reloc_table + reloc_table->SizeOfBlock );
    }
}



#pragma check_stack( off )
DECLSPEC_SAFEBUFFERS DECLSPEC_NOINLINE static void fix_data_dirs( void )
{
    void* base = get_module_handle( 0 );
    PEHeader pe( base );

    DWORD old_prot;
    size_t hdrs_size = pe.optional_hdr()->SizeOfHeaders;
    pNtProtectVirtualMemory( NtCurrentProcess, &base, &hdrs_size, PAGE_READWRITE, &old_prot );

    for ( int i = 0; i < _countof( DataDirectory ); i++ ) {
        *pe.data_dir( i ) = DataDirectory[i];
    }

    pNtProtectVirtualMemory( NtCurrentProcess, &base, &hdrs_size, old_prot, &old_prot );
    
    fix_import_dir( pe );
    fix_reloc_dir( pe );
}




#pragma check_stack( off )
extern "C" DECLSPEC_NOINLINE void unpack( void )
{
    stub_init();
    decompress_sections();
    fix_data_dirs();

    char* base = (char*)get_module_handle( 0 );

    ( ( void ( * )( void ) )( base + OriginalEntryPoint ) )();
}










#pragma comment( linker, "/include:unpack" )
#pragma code_seg( pop )