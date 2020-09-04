#pragma once
#include <Windows.h>
#include "pe.h"
#include "miniz-2.1.0/miniz.h"

extern "C" IMAGE_DOS_HEADER __ImageBase;

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
        size_t total_size = 0;

        for ( auto section : pe.get_sections() ) {
            
            void* pCmp = nullptr;
            size_t cmp_len = 0;

            if ( _compress( section->data, section->hdr.SizeOfRawData, &pCmp, &cmp_len ) ) {
                
                printf( "Compressed section: %s\n", section->hdr.Name );

                size_t cmp_len_align = pe.align_up( cmp_len, pe.optional_hdr()->FileAlignment );
                total_size += cmp_len_align;

                free( section->data );

                section->data = pCmp;
                section->hdr.PointerToRawData = (DWORD)total_size;
                section->hdr.SizeOfRawData = (DWORD)cmp_len_align;
                section->hdr.PointerToLinenumbers = (DWORD)cmp_len;
                
                // TODO: Remove. Its for debugging only
                memcpy( section->data, section->hdr.Name, 8 );
                section->hdr.Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
                
            }

        }


        PEHeader own( &__ImageBase );


        IMAGE_SECTION_HEADER stub_section_hdr = *own.section_hdr( ".stub" );

        void* stub_section_data = own.rva2va( stub_section_hdr.VirtualAddress );

        pe.section_add( &stub_section_hdr, stub_section_data );


        return true;
    }
};