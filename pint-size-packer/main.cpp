#include <stdio.h>
#include "pe.h"

int main( int argc, char** argv )
{
    if ( argc != 2 ) {
        return printf( "Usage: %s <infile>\n", argv[0] );
    }

    PEFile pe( argv[1] );

    pe.save( "psp2.exe" );


    return 0;
}