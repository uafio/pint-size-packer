#pragma once
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <assert.h>
#include "strings.h"

class Section
{
private:
public:
    IMAGE_SECTION_HEADER hdr;
    void* data;

    Section( PIMAGE_SECTION_HEADER hdr, void* data, size_t size )
    {
        this->hdr = *hdr;
        this->data = malloc( size );
        memcpy( this->data, data, size );
    }

    ~Section( void )
    {
        if ( data ) {
            free( data );
            data = nullptr;
        }
        memset( &hdr, 0, sizeof( hdr ) );
    }
};

class PEFile
{
private:
    void* data;
    size_t size;
    std::vector< Section* > sections;
    PEFile( const PEFile& );

    bool get_file_content( const char* fpath )
    {
        std::ifstream file( fpath, std::fstream::binary | std::fstream::ate );
        if ( !file.is_open() ) {
            return false;
        }

        size = file.tellg();
        data = calloc( size, 1 );

        file.seekg( std::fstream::beg );
        file.read( reinterpret_cast< char* >( data ), size );

        return true;
    }

    void sections_update( void )
    {
        uint32_t raw = size_of_headers();
        uint32_t rav = align_section( raw );

        for ( auto section : sections ) {
            section->hdr.PointerToRawData = raw;
            section->hdr.VirtualAddress = rav;

            raw += section->hdr.SizeOfRawData;
            rav += align_section( section->hdr.Misc.VirtualSize );
        }
    }

    template< class T >
    T align_up( T addr, size_t alignment )
    {
        size_t pad = (uintptr_t)addr % alignment;
        if ( pad ) {
            return (uintptr_t)addr + alignment - pad;
        }
        return addr;
    }


    PIMAGE_SECTION_HEADER section_hdr( uint32_t index )
    {
        return IMAGE_FIRST_SECTION( nt_hdr() ) + index;
    }


    PIMAGE_SECTION_HEADER section_hdr( const char* name )
    {
        for ( int i = 0; i < file_hdr()->NumberOfSections; i++ ) {
            auto section = section_hdr( i );

            if ( strncmp( name, reinterpret_cast< char* >( section->Name ), sizeof( section->Name ) ) == 0 ) {
                return section;
            }
        }
        return nullptr;
    }

    void* section_data( uint32_t index )
    {
        return reinterpret_cast< char* >( data ) + section_hdr( index )->PointerToRawData;
    }



public:
    PEFile( const char* fpath )
        : data( nullptr ), size( 0 )
    {
        if ( get_file_content( fpath ) ) {
            for ( int i = 0; i < file_hdr()->NumberOfSections; i++ ) {
                auto shdr = section_hdr( i );
                auto sdata = section_data( i );
                sections.push_back( new Section( shdr, sdata, shdr->SizeOfRawData ) );
            }
        }
    }

    ~PEFile( void )
    {
        if ( data ) {
            free( data );
            data = nullptr;
            size = 0;
        }

        for ( auto sec : sections ) {
            delete sec;
        }

        sections.clear();
    }

    std::vector< Section* >& get_sections( void )
    {
        return sections;
    }

    PIMAGE_DOS_HEADER pe_hdr( void )
    {
        return reinterpret_cast< PIMAGE_DOS_HEADER >( data );
    }

    PIMAGE_NT_HEADERS64 nt_hdr( void )
    {
        return reinterpret_cast< PIMAGE_NT_HEADERS64 >( reinterpret_cast< uintptr_t >( data ) + pe_hdr()->e_lfanew );
    }

    PIMAGE_FILE_HEADER file_hdr( void )
    {
        return &nt_hdr()->FileHeader;
    }

    PIMAGE_OPTIONAL_HEADER64 optional_hdr( void )
    {
        return &nt_hdr()->OptionalHeader;
    }

    PIMAGE_DATA_DIRECTORY data_dir( size_t index )
    {
        return &optional_hdr()->DataDirectory[index];
    }


    size_t rva2fo( size_t rva )
    {
        if ( rva <= section_hdr( 0U )->PointerToRawData ) {
            return rva;
        }

        for ( int i = 0; i < file_hdr()->NumberOfSections; i++ ) {
            auto section = section_hdr( i );

            if ( rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize ) {
                rva -= section->VirtualAddress;

                if ( rva >= section->SizeOfRawData ) {
                    return section->PointerToRawData;
                }
                return rva + section->PointerToRawData;
            }
        }

        return 0;
    }


    Section* section( const char* name )
    {
        for ( auto section : sections ) {
            if ( strncmp( name, reinterpret_cast< char* >( section->hdr.Name ), sizeof( section->hdr.Name ) ) == 0 ) {
                return section;
            }
        }

        return nullptr;
    }

    bool section_add( PIMAGE_SECTION_HEADER shdr, void* sdata )
    {
        PIMAGE_SECTION_HEADER lastsechdr = &sections.back()->hdr;

        shdr->VirtualAddress = align_section( lastsechdr->VirtualAddress + lastsechdr->Misc.VirtualSize );
        shdr->PointerToRawData = align_file( lastsechdr->PointerToRawData + lastsechdr->SizeOfRawData );

        sections.push_back( new Section( shdr, sdata, shdr->SizeOfRawData ) );

        file_hdr()->NumberOfSections++;
        optional_hdr()->SizeOfImage += align_section( shdr->Misc.VirtualSize );
        optional_hdr()->SizeOfHeaders = (DWORD)size_of_headers();

        return true;
    }

    uint32_t size_of_headers( void )
    {
        uint32_t result = 0;

        result += pe_hdr()->e_lfanew;
        result += sizeof( IMAGE_NT_HEADERS64 );
        result += sizeof( IMAGE_SECTION_HEADER ) * (uint32_t)sections.size();

        return align_file( result );
    }

    uint32_t align_file( uint32_t value )
    {
        return (uint32_t)align_up< size_t >( value, optional_hdr()->FileAlignment );
    }

    uint32_t align_section( uint32_t value )
    {
        return (uint32_t)align_up< size_t >( value, optional_hdr()->SectionAlignment );
    }

    bool save( const char* fname )
    {
        std::ofstream ofile( fname, std::fstream::binary );
        if ( !ofile.is_open() ) {
            std::perror( __FUNCTION__ );
            return false;
        }

        sections_update();

        file_hdr()->NumberOfSections = (WORD)sections.size();

        ofile.write( reinterpret_cast< char* >( pe_hdr() ), pe_hdr()->e_lfanew );
        ofile.write( reinterpret_cast< char* >( nt_hdr() ), sizeof( IMAGE_NT_HEADERS64 ) );

        for ( auto section : sections ) {
            ofile.write( reinterpret_cast< char* >( &section->hdr ), sizeof( IMAGE_SECTION_HEADER ) );
        }

        size_t pad = optional_hdr()->SizeOfHeaders - ofile.tellp();
        while ( pad-- ) {
            ofile.write( "\x00", 1 );
        }

        for ( auto section : sections ) {
            ofile.write( reinterpret_cast< char* >( section->data ), section->hdr.SizeOfRawData );

            pad = align_file( section->hdr.SizeOfRawData ) - section->hdr.SizeOfRawData;
            while ( pad-- ) {
                assert( false ); // Debugging: Should not happen
                ofile.write( "\x00", 1 );
            }
        }

        return true;
    }
};

class PEHeader
{
private:
    void* base;

public:
    __forceinline PEHeader( void* addr )
        : base( addr )
    {
    }

    __forceinline void* get_base( void )
    {
        return base;
    }

    __forceinline void* rva2va( size_t rva )
    {
        return reinterpret_cast< char* >( base ) + rva;
    }

    __forceinline PIMAGE_DOS_HEADER pe_hdr( void )
    {
        return reinterpret_cast< PIMAGE_DOS_HEADER >( base );
    }

    __forceinline PIMAGE_NT_HEADERS64 nt_hdr( void )
    {
        return reinterpret_cast< PIMAGE_NT_HEADERS64 >( reinterpret_cast< uintptr_t >( base ) + pe_hdr()->e_lfanew );
    }

    __forceinline PIMAGE_FILE_HEADER file_hdr( void )
    {
        return &nt_hdr()->FileHeader;
    }

    __forceinline PIMAGE_OPTIONAL_HEADER64 optional_hdr( void )
    {
        return &nt_hdr()->OptionalHeader;
    }

    __forceinline PIMAGE_DATA_DIRECTORY data_dir( size_t index )
    {
        return &optional_hdr()->DataDirectory[index];
    }

    __forceinline PIMAGE_SECTION_HEADER section_hdr( uint32_t index )
    {
        return IMAGE_FIRST_SECTION( nt_hdr() ) + index;
    }

    __forceinline PIMAGE_SECTION_HEADER section_hdr( const char* sname )
    {
        for ( int i = 0; i < file_hdr()->NumberOfSections; i++ ) {
            auto section = section_hdr( i );

            if ( stub_strncmp( sname, reinterpret_cast< char* >( section->Name ), sizeof( section->Name ) ) == 0 ) {
                return section;
            }
        }
        return nullptr;
    }

    template< class T >
    __forceinline T align_up( T addr, size_t alignment )
    {
        size_t pad = (uintptr_t)addr % alignment;
        if ( pad ) {
            return (uintptr_t)addr + alignment - pad;
        }
        return addr;
    }
};
