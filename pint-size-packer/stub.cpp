#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "strings.h"
#include "pe.h"
#include "miniz-2.1.0/miniz.h"

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
STUB_DATA uint32_t OriginalEntryPoint;

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
STUB_DATA char sStubSectionName[] = ".stub";



#pragma check_stack( off )
__declspec( safebuffers ) DECLSPEC_NOINLINE void* get_module_address( const wchar_t* name )
{
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
__declspec( safebuffers ) DECLSPEC_NOINLINE void* get_proc_address( void* hModule, char* apiname )
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
__declspec( safebuffers ) DECLSPEC_NOINLINE static void stub_init( void )
{
    pKernel32 = get_module_address( wcKernel32 );
    pNtdll = get_module_address( wcNtdll );

    _ReadWriteBarrier();

    pGetProcAddress = (GetProcAddress_t)get_proc_address( pKernel32, sGetProcAddress );
    pLoadLibraryA = (LoadLibraryA_t)get_proc_address( pKernel32, sLoadLibraryA );
    pNtFreeVirtualMemory = (NtFreeVirtualMemory_t)get_proc_address( pNtdll, sNtFreeVirtualMemory );
    pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)get_proc_address( pNtdll, sNtAllocateVirtualMemory );
    pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)get_proc_address( pNtdll, sNtProtectVirtualMemory );

    _ReadWriteBarrier();
}



__declspec( safebuffers ) DECLSPEC_NOINLINE static void decompress_sections( void )
{
    PEHeader pe( NtCurrentTeb()->ProcessEnvironmentBlock->Reserved3[1] );

    for ( int i = 0; i < pe.file_hdr()->NumberOfSections; i++ ) {
    
        PIMAGE_SECTION_HEADER section = pe.section_hdr( i );
        if ( section->PointerToLinenumbers == 0 ) {
            continue;
        }
        
        uint8_t* pCmp = (uint8_t*)pe.rva2va( section->VirtualAddress );
        uint8_t* pUncomp = nullptr;
        mz_ulong cmp_len = section->PointerToLinenumbers;
        size_t uncomp_len = pe.align_up< size_t >( section->Misc.VirtualSize, pe.optional_hdr()->SectionAlignment );

        pNtAllocateVirtualMemory( (HANDLE)-1, (void**)&pUncomp, NULL, &uncomp_len, MEM_COMMIT, PAGE_READWRITE );

        uncompress( pUncomp, (mz_ulong*)&uncomp_len, pCmp, cmp_len );
        
        stub_memcpy( pCmp, pUncomp, uncomp_len );

        pNtFreeVirtualMemory( (HANDLE)-1, (void**)&pUncomp, &uncomp_len, MEM_RELEASE );

    }
}


#pragma check_stack( off )
extern "C" DECLSPEC_NOINLINE DECLSPEC_NORETURN void unpack( void )
{
    stub_init();
    decompress_sections();

    char* base = (char*)NtCurrentTeb()->ProcessEnvironmentBlock->Reserved3[1];

    ( ( void ( * )( void ) )( base + OriginalEntryPoint ) )();

}










#pragma comment( linker, "/include:unpack" )
#pragma code_seg( pop )