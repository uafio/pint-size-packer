#pragma once
#include <Windows.h>
#include <stdint.h>
#include "pe.h"
#include "miniz-2.1.0/miniz.h"

extern "C" IMAGE_DOS_HEADER __ImageBase;
extern "C" void unpack( void );
extern uint32_t OriginalEntryPoint;

class Packer
{
private:
    Packer( const Packer& );
    PEFile& pe;

    bool _compress( void* data, size_t size, void** ppCmp, size_t* pCmpSize )
    {
        uLong cmp_len = compressBound( (mz_ulong)size );
        const size_t cmp_len_align = pe.align_up< size_t >( cmp_len, pe.optional_hdr()->FileAlignment );

        uint8_t* pCmp = (mz_uint8*)calloc( cmp_len_align, 1 );

        int cmp_status = compress( pCmp, &cmp_len, (const unsigned char*)data, (mz_ulong)size );

        *ppCmp = pCmp;
        *pCmpSize = cmp_len;

        return cmp_status == Z_OK;
    }

public:
    Packer( PEFile& pefile )
        : pe( pefile )
    {
    }

    virtual bool pack( void )
    {
        auto alignment = pe.optional_hdr()->FileAlignment;

        for ( int i = 0; i < pe.get_sections().size(); i++ ) {

            Section* section = pe.get_sections().at( i );
            if ( section->hdr.SizeOfRawData <= pe.optional_hdr()->FileAlignment ) {
                continue;
            }
            printf( "packing section: %s\n", section->hdr.Name );

            void* pCmp = nullptr;
            size_t cmp_len = 0;

            if ( _compress( section->data, section->hdr.SizeOfRawData, &pCmp, &cmp_len ) ) {
                size_t cmp_len_align = pe.align_up( cmp_len, pe.optional_hdr()->FileAlignment );

                free( section->data );

                section->data = pCmp;
                section->hdr.SizeOfRawData = (DWORD)cmp_len_align;
                section->hdr.PointerToLinenumbers = (DWORD)cmp_len;

                section->hdr.Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
            }

        }



        OriginalEntryPoint = pe.optional_hdr()->AddressOfEntryPoint;

        PEHeader own( &__ImageBase );

        IMAGE_SECTION_HEADER stub_section_hdr = *own.section_hdr( ".stub" );

        stub_section_hdr.Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

        void* stub_section_data = own.rva2va( stub_section_hdr.VirtualAddress );

        pe.section_add( &stub_section_hdr, stub_section_data );

        size_t offset = (uintptr_t)unpack - (uintptr_t)own.rva2va( own.section_hdr( ".stub" )->VirtualAddress );

        pe.optional_hdr()->AddressOfEntryPoint = stub_section_hdr.VirtualAddress + (DWORD)offset;


        // These can be corrupted

        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_IMPORT )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_IMPORT )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_EXCEPTION )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_EXCEPTION )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_DEBUG )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_DEBUG )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_BASERELOC )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_BASERELOC )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_SECURITY )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_SECURITY )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_ARCHITECTURE )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_ARCHITECTURE )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_GLOBALPTR )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_GLOBALPTR )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT )->VirtualAddress = 0;


        // TODO: These need fixing
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_EXPORT )->Size = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_EXPORT )->VirtualAddress = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_IAT )->Size = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_IAT )->VirtualAddress = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_RESOURCE )->Size = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_RESOURCE )->VirtualAddress = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG )->Size = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG )->VirtualAddress = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_TLS )->Size = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_TLS )->VirtualAddress = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR )->Size = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR )->VirtualAddress = 0;
        

        return true;
    }
};