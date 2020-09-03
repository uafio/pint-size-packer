#include <Windows.h>
#include <stdio.h>

#pragma section( ".stub", read, execute )

#define STUB_DATA __declspec( allocate( ".stub" ) )

STUB_DATA size_t stub_OriginalEntryPoint;
STUB_DATA char test[] = "test";

#pragma code_seg( push, ".stub" )

extern "C" DECLSPEC_NOINLINE DECLSPEC_NORETURN void unpack( void )
{
    puts( test );
}

#pragma comment( linker, "/include:unpack" )

#pragma code_seg( pop, ".stub" )