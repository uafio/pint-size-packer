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
        stub_memcpy( DataDirectory, pe.data_dir( 0 ), sizeof( DataDirectory ) );

        // Save section headers so we know how to unpack them.
        NumberOfSections = (DWORD)pe.sections.get().size();

        for ( int i = 0; i < pe.sections.get().size(); i++ ) {
            SectionHeaders[i] = pe.sections.get().at( i )->hdr;
        }
    }



public:
    Packer( void )
    {
    }

    virtual bool pack( PE& pe )
    {
        Section* rsrc = pe.sections[".rsrc"];
        Section* rcopy = nullptr;
        if ( rsrc ) {
            rcopy = new Section( &rsrc->hdr, nullptr, 0 );
            rcopy->hdr.SizeOfRawData = 0;
            rcopy->hdr.Name[5] = '2';
            pe.sections.replace( rsrc, rcopy );
            pe.update_headers();
        }

        save_stub_externs( pe );

        pe.sections.merge();

        void* pCmp = nullptr;
        uint32_t pCmpSize = 0;
        Section* section = pe.sections.get().front();

        _compress( section->data, section->hdr.SizeOfRawData, &pCmp, &pCmpSize, pe );
        if ( pCmp && pCmpSize ) {
            section->hdr.PointerToLinenumbers = section->hdr.SizeOfRawData;
            section->hdr.SizeOfRawData = pe.align_file( pCmpSize );
            free( section->data );
            section->data = pCmp;
        }



        // Add .stub section to the new exe
        PEHeader own( &__ImageBase );

        IMAGE_SECTION_HEADER stub_section_hdr = *own.section_hdr( ".stub" );
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

        pe.sections[".psp0"]->hdr.Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        pe.sections[".psp1"]->hdr.Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;


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
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_BASERELOC )->Size = 0;
        pe.data_dir( IMAGE_DIRECTORY_ENTRY_BASERELOC )->VirtualAddress = 0;

        if ( rsrc ) {
            pe.data_dir( IMAGE_DIRECTORY_ENTRY_RESOURCE )->VirtualAddress = rsrc->hdr.VirtualAddress;
        }


        return true;
    }
};