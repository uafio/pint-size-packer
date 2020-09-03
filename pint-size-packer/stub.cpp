#include <Windows.h>
#include <stdio.h>

#pragma code_seg( push, ".stub" )


#define STUB_DATA __declspec( allocate( ".stub" ) )



STUB_DATA char test[] = "test";

extern "C" DECLSPEC_NOINLINE void unpack( void )
{
    puts( test );
}










#pragma comment( linker, "/include:unpack" )
#pragma code_seg( pop )