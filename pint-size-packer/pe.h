#pragma once
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <fstream>
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

    constexpr inline char separator( void )
    {
#if _WIN32
        return '\\';
#else
        return '/';
#endif
    }


public:
    PEFile( const char* fpath )
        : data( nullptr ), size( 0 )
    {
        if ( get_file_content( fpath ) ) {
            for ( int i = 0; i < file_hdr()->NumberOfSections; i++ ) {
                auto shdr = section_hdr( i );
                auto sdata = section( i );
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

    template< class T >
    T align_up( T addr, size_t alignment )
    {
        size_t pad = (uintptr_t)addr % alignment;
        if ( pad ) {
            return (uintptr_t)addr + alignment - pad;
        }
        return addr;
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


    void* section( uint32_t index )
    {
        if ( index < sections.size() ) {
            return sections.at( index )->data;
        }

        return reinterpret_cast< char* >( data ) + section_hdr( index )->PointerToRawData;
    }

    void* section( const char* name )
    {
        if ( sections.size() ) {

            for ( auto section : sections ) {
            
                if ( strncmp( name, reinterpret_cast< char* >( section->hdr.Name ), sizeof( section->hdr.Name ) ) == 0 ) {
                    return section->data;
                }
            
            }

            return nullptr;
            
        }
        return reinterpret_cast< char* >( data ) + section_hdr( name )->PointerToRawData;
    }


    bool section_add( PIMAGE_SECTION_HEADER shdr, void* sdata )
    {
        PIMAGE_SECTION_HEADER lastsechdr = &sections.back()->hdr;

        shdr->VirtualAddress = (DWORD)align_up< size_t >( lastsechdr->VirtualAddress + lastsechdr->Misc.VirtualSize, optional_hdr()->SectionAlignment );
        shdr->PointerToRawData = lastsechdr->PointerToRawData + lastsechdr->SizeOfRawData;

        sections.push_back( new Section( shdr, sdata, shdr->SizeOfRawData ) );

        file_hdr()->NumberOfSections++;

        optional_hdr()->SizeOfImage += (DWORD)align_up< size_t >( shdr->Misc.VirtualSize, optional_hdr()->SectionAlignment );

        if ( size_of_headers() > optional_hdr()->SizeOfHeaders ) {
        
            optional_hdr()->SizeOfHeaders = (DWORD)size_of_headers();
        
        }

        return true;
    }



    size_t size_of_headers( void )
    {
        size_t result = 0;

        result += pe_hdr()->e_lfanew;
        result += sizeof( IMAGE_NT_HEADERS64 );
        result += sizeof( IMAGE_SECTION_HEADER ) * sections.size();

        return align_up< size_t >( result, optional_hdr()->FileAlignment );
    }



    bool save( const char* fname )
    {
        std::ofstream ofile( fname, std::fstream::binary );
        if ( !ofile.is_open() ) {
            std::perror( __FUNCTION__ );
            return false;
        }

        ofile.write( reinterpret_cast< char* >( pe_hdr() ), pe_hdr()->e_lfanew );
        ofile.write( reinterpret_cast< char* >( nt_hdr() ), sizeof( IMAGE_NT_HEADERS64 ) );

        DWORD raw = (DWORD)size_of_headers();
        DWORD rva = (DWORD)align_up< size_t >( raw, optional_hdr()->SectionAlignment );

        for ( auto section : sections ) {
        
            PIMAGE_SECTION_HEADER shdr = &section->hdr;
            shdr->VirtualAddress = rva;
            shdr->PointerToRawData = raw;

            rva = (DWORD)align_up< size_t >( rva + shdr->Misc.VirtualSize, optional_hdr()->SectionAlignment );
            raw = (DWORD)align_up< size_t >( raw + shdr->SizeOfRawData, optional_hdr()->FileAlignment );

            ofile.write( reinterpret_cast< char* >( &section->hdr ), sizeof( IMAGE_SECTION_HEADER ) );
            
        }

        size_t pad = optional_hdr()->SizeOfHeaders - ofile.tellp();
        while ( pad-- ) {
            ofile.write( "\x00", 1 );
        }

        for ( auto section : sections ) {
            ofile.write( reinterpret_cast< char* >( section->data ), section->hdr.SizeOfRawData );
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


