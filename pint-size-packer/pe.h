#pragma once
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <fstream>


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
    const char* fpath;
    const char* fname;
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
        : fpath( nullptr ), fname( nullptr ), data( nullptr ), size( 0 )
    {
        this->fpath = reinterpret_cast< const char* >( calloc( _MAX_PATH, 1 ) );
        strcpy_s( const_cast< char* >( this->fpath ), _MAX_PATH, fpath );
        fname = strrchr( this->fpath, separator() );
        
        if ( fname == nullptr ) {
            fname = fpath;
        }
        
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
        fname = nullptr;

        if ( fpath ) {
            free( const_cast< char* >( fpath ) );
            fpath = nullptr;
        }

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



    void* section( uint32_t index )
    {
        return reinterpret_cast< char* >( data ) + section_hdr( index )->PointerToRawData;
    }



    void* section( const char* name )
    {
        return reinterpret_cast< char* >( data ) + section_hdr( name )->PointerToRawData;
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



    bool save( const char* fname )
    {
        std::ofstream ofile( fname, std::fstream::binary );
        if ( !ofile.is_open() ) {
            std::perror( __FUNCTION__ );
            return false;
        }

        size_t hdrs_size = reinterpret_cast< uintptr_t >( section_hdr( 0U ) ) - reinterpret_cast< uintptr_t >( pe_hdr() );
        ofile.write( reinterpret_cast< char* >( pe_hdr() ), hdrs_size );

        if ( (DWORD)ofile.tellp() + sections.size() * sizeof( sections[0]->hdr ) > section_hdr( 0U )->PointerToRawData ) {
            for ( auto sec : sections ) {
                sec->hdr.PointerToRawData += optional_hdr()->FileAlignment;
            }
        }

        for ( auto section : sections ) {
            ofile.write( reinterpret_cast< char* >( &section->hdr ), sizeof( section->hdr ) );
        }

        auto pad = ofile.tellp() % optional_hdr()->FileAlignment;
        if ( pad ) {
            pad = optional_hdr()->FileAlignment - pad;
            while ( pad-- ) {
                ofile.write( "\x00", 1 );
            }
        }

        for ( auto section : sections ) {
            ofile.write( reinterpret_cast< char* >( section->data ), section->hdr.SizeOfRawData );
        }

        return true;
    }



    bool section_add( PIMAGE_SECTION_HEADER shdr, void* sdata )
    {
        PIMAGE_SECTION_HEADER lastsechdr = section_hdr( file_hdr()->NumberOfSections - 1 );

        shdr->VirtualAddress = (DWORD)align_up< size_t >( lastsechdr->VirtualAddress + lastsechdr->Misc.VirtualSize, optional_hdr()->SectionAlignment );
        shdr->PointerToRawData = lastsechdr->PointerToRawData + lastsechdr->SizeOfRawData;

        sections.push_back( new Section( shdr, sdata, shdr->SizeOfRawData ) );

        file_hdr()->NumberOfSections++;
        optional_hdr()->SizeOfImage += (DWORD)align_up< size_t >( shdr->Misc.VirtualSize, optional_hdr()->SectionAlignment );

        return true;
    }

};

