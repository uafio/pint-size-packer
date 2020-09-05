#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include "pe.h"
#include "miniz-2.1.0/miniz.h"
#include "packer.h"


int main( int argc, char** argv )
{
    if ( argc != 2 ) {
        return printf( "Usage: %s <infile>\n", argv[0] );
    }

    PEFile input( argv[1] );

    Packer packer( input );

    packer.pack();


    input.save( "packed.exe" );


    return 0;
}