#pragma once
#include <Windows.h>
#include <stdint.h>
#include "pe.h"
#include "miniz-2.1.0/miniz.h"

extern "C" IMAGE_DOS_HEADER __ImageBase;
extern "C" void unpack( void );
extern size_t ImageBase;
extern uint32_t OriginalEntryPoint;
extern uint32_t NumberOfSections;
extern IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
extern IMAGE_SECTION_HEADER SectionHeaders[20];


class Packer
{
private:
    Packer( const Packer& );

    bool _compress( void* data, size_t size, void** ppCmp, uint32_t* pCmpSize, PE& pe )
    {
        uLong cmp_len = compressBound( (mz_ulong)size );
        const size_t cmp_len_align = pe.align_file( cmp_len );

        uint8_t* pCmp = (mz_uint8*)calloc( cmp_len_align, 1 );

        int cmp_status = compress( pCmp, &cmp_len, (const unsigned char*)data, (mz_ulong)size );

        *ppCmp = pCmp;
        *pCmpSize = cmp_len;

        return cmp_status == Z_OK;
    }

    void save_stub_externs( PE& pe )
    {
        // Save ImageBase from the header for the relocations
        ImageBase = pe.optional_hdr()->ImageBase;

        // Save OEP
        OriginalEntryPoint = pe.optional_hdr()->AddressOfEntryPoint;

        // Save the DATA_DIRECTORIES for the unpacker
        memcpy( DataDirectory, pe.data_dir( 0 ), sizeof( DataDirectory ) );

        // Save section headers so we know how to unpack them.
        NumberOfSections = pe.file_hdr()->NumberOfSections;
        memcpy( SectionHeaders, pe.section_hdr( 0U ), sizeof( IMAGE_SECTION_HEADER ) * pe.file_hdr()->NumberOfSections );
    }



public:
    Packer( void )
    {
    }

    virtual bool pack( PE& pe )
    {
        save_stub_externs( pe );

        Section* rsrc = pe.sections.pop( ".rsrc" );

        pe.sections.merge();

        // Add .stub section to the new exe
        PEHeader own( &__ImageBase );

        IMAGE_SECTION_HEADER stub_section_hdr = *own.section_hdr( ".stub" );
        stub_section_hdr.Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        void* stub_section_data = own.rva2va( stub_section_hdr.VirtualAddress );

        pe.sections.add( new Section( &stub_section_hdr, stub_section_data, stub_section_hdr.SizeOfRawData ) );


        if ( rsrc ) {
            pe.sections.add( rsrc );
        }

        pe.update_headers();

        // Change the Entry Point to the unpacker
        uint32_t offset2section = ( uint32_t )( (uintptr_t)unpack - (uintptr_t)own.rva2va( own.section_hdr( ".stub" )->VirtualAddress ) );
        pe.optional_hdr()->AddressOfEntryPoint = pe.sections[".stub"]->hdr.VirtualAddress + offset2section;

        pe.sections.rename( pe.sections.get().at( 0 ), ".psp0" );
        pe.sections.rename( pe.sections.get().at( 1 ), ".psp1" );


        // These can be corrupted at program load, we restore them later anyway

        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_EXPORT )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_EXPORT )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_IMPORT )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_IMPORT )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_IAT )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_IAT )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_EXCEPTION )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_EXCEPTION )->VirtualAddress = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_DEBUG )->Size = 0;
        // pe.data_dir( IMAGE_DIRECTORY_ENTRY_DEBUG )->VirtualAddress = 0;
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


        // Unsupported for now. This section can't be compressed or the application will lose its resources
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_RESOURCE )->Size = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_RESOURCE )->VirtualAddress = 0;

        // Unsupported SafeSEH
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG )->Size = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG )->VirtualAddress = 0;

        // Unsupported TLS callbacks
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_TLS )->Size = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_TLS )->VirtualAddress = 0;

        // Unsupported .NET
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR )->Size = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR )->VirtualAddress = 0;

        // We don't want Windows to corrupt our compressed data by trying to resolve relocations
        if ( rsrc ) {
            pe.data_dir( IMAGE_DIRECTORY_ENTRY_BASERELOC )->VirtualAddress = rsrc->hdr.VirtualAddress;
        }


        return true;
    }
};