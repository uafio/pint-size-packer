#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "strings.h"
#include "pe.h"

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



#pragma check_stack( off )
__declspec( safebuffers ) extern "C" DECLSPEC_NOINLINE void unpack( void )
{
    stub_init();
}










#pragma comment( linker, "/include:unpack" )
#pragma code_seg( pop )