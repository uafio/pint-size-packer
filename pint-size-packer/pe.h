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

class Sections
{
private:
    std::vector< Section* > sections;

public:
    Sections( void )
    {
        sections.reserve( 20 );
    }

    ~Sections( void )
    {
        clear();
    }

    void clear( void )
    {
        for ( auto section : sections ) {
            delete section;
        }

        sections.clear();
    }

    void add( Section* section )
    {
        sections.push_back( section );
    }

    std::vector< Section* >& get( void )
    {
        return sections;
    }

    Section* pop( const char* name )
    {
        for ( auto it = sections.begin(); it != sections.end(); it++ ) {
            if ( strncmp( name, reinterpret_cast< char* >( ( *it )->hdr.Name ), 8 ) == 0 ) {
                Section* result = *it;
                sections.erase( it );
                return result;
            }
        }

        return nullptr;
    }

    Section* operator[]( const char* name )
    {
        for ( auto section : sections ) {
            if ( strncmp( name, reinterpret_cast< char* >( section->hdr.Name ), 8 ) == 0 ) {
                return section;
            }
        }

        return nullptr;
    }

    bool rename( const char* name, const char* newname )
    {
        Section* section = this->operator[]( name );
        if ( section ) {
            memset( section->hdr.Name, 0, 8 );
            strncpy( reinterpret_cast< char* >( section->hdr.Name ), newname, 8 );
            return true;
        }

        return false;
    }

    void rename( Section* section, const char* name )
    {
        memset( section->hdr.Name, 0, 8 );
        strncpy( reinterpret_cast< char* >( section->hdr.Name ), name, 8 );
    }

    void merge( void )
    {
        uint32_t rawsize = 0;
        uint32_t vasz = 0;
        for ( auto section : sections ) {
            rawsize += section->hdr.SizeOfRawData;
            vasz += section->hdr.Misc.VirtualSize;
        }

        uint8_t* data = reinterpret_cast< uint8_t* >( calloc( rawsize, 1 ) );

        IMAGE_SECTION_HEADER hdr = sections.at( 0 )->hdr;

        hdr.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        hdr.Misc.VirtualSize = vasz;
        hdr.SizeOfRawData = rawsize;

        uint32_t offset = 0;

        for ( auto section : sections ) {
            memcpy( &data[offset], section->data, section->hdr.SizeOfRawData );
            offset += section->hdr.SizeOfRawData;
        }
        assert( offset == rawsize );

        Section* newsection = new Section( &hdr, data, rawsize );

        clear();
        add( newsection );
    }
};

class PEHeader
{
protected:
    void* base;

public:
    __forceinline PEHeader( void )
        : base( nullptr )
    {
    }

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

    __forceinline void* section_data( uint32_t index )
    {
        return reinterpret_cast< char* >( base ) + section_hdr( index )->PointerToRawData;
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

    __forceinline size_t rva2fo( size_t rva )
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
};

class PE : public PEHeader
{
private:
    size_t size;

    bool get_file_content( const char* fpath )
    {
        std::ifstream file( fpath, std::fstream::binary | std::fstream::ate );
        if ( !file.is_open() ) {
            return false;
        }

        size = file.tellg();
        base = calloc( size, 1 );

        file.seekg( std::fstream::beg );
        file.read( reinterpret_cast< char* >( base ), size );

        return true;
    }

public:
    Sections sections;

    PE( const char* fpath )
        : size( 0 )
    {
        if ( get_file_content( fpath ) ) {
            for ( int i = 0; i < file_hdr()->NumberOfSections; i++ ) {
                auto shdr = section_hdr( i );
                shdr->Misc.VirtualSize = align_section( shdr->Misc.VirtualSize );
                auto sdata = section_data( i );
                sections.add( new Section( shdr, sdata, shdr->SizeOfRawData ) );
            }
        }
    }

    ~PE( void )
    {
        if ( base ) {
            free( base );
            base = nullptr;
            size = 0;
        }
    }

    void update_headers( void )
    {
        uint32_t raw = size_of_headers();
        uint32_t rav = align_section( raw );

        for ( auto section : sections.get() ) {
            section->hdr.PointerToRawData = raw;
            section->hdr.VirtualAddress = rav;

            raw += section->hdr.SizeOfRawData;
            rav += align_section( section->hdr.Misc.VirtualSize );
        }

        file_hdr()->NumberOfSections = (WORD)sections.get().size();
        optional_hdr()->SizeOfHeaders = size_of_headers();
        optional_hdr()->SizeOfImage = sections.get().back()->hdr.VirtualAddress + sections.get().back()->hdr.Misc.VirtualSize;
    }

    uint32_t size_of_headers( void )
    {
        uint32_t result = 0;

        result += pe_hdr()->e_lfanew;
        result += sizeof( IMAGE_NT_HEADERS64 );
        result += sizeof( IMAGE_SECTION_HEADER ) * (uint32_t)sections.get().size();

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

        update_headers();

        file_hdr()->NumberOfSections = (WORD)sections.get().size();

        ofile.write( reinterpret_cast< char* >( pe_hdr() ), pe_hdr()->e_lfanew );
        ofile.write( reinterpret_cast< char* >( nt_hdr() ), sizeof( IMAGE_NT_HEADERS64 ) );

        for ( auto section : sections.get() ) {
            ofile.write( reinterpret_cast< char* >( &section->hdr ), sizeof( IMAGE_SECTION_HEADER ) );
        }

        size_t pad = optional_hdr()->SizeOfHeaders - ofile.tellp();
        while ( pad-- ) {
            ofile.write( "\x00", 1 );
        }

        for ( auto section : sections.get() ) {
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
