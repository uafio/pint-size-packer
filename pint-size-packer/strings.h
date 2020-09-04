#pragma once


__forceinline size_t stub_strlen( const char* s )
{
    const char* d = s;
    while ( *d++ )
        ;
    return d - s;
}

__forceinline size_t stub_strlen( const wchar_t* s )
{
    const wchar_t* d = s;
    while ( *d++ )
        ;
    return ( ( d - s ) >> 1 );
}


__forceinline char* stub_strchr( const char* s, int c )
{
    do {
        if ( *s == c ) {
            return (char*)s;
        }
    } while ( *s++ );

    return nullptr;
}


__forceinline wchar_t* stub_strchr( const wchar_t* s, int c )
{
    do {
        if ( *s == c ) {
            return (wchar_t*)s;
        }
    } while ( *s++ );

    return nullptr;
}


__forceinline char* stub_strrchr( const char* s, int c )
{
    const char *found, *p;
    c = (unsigned char)c;

    if ( c == 0 ) {
        return stub_strchr( s, 0 );
    }

    found = nullptr;
    
    while ( ( p = stub_strchr( s, c ) ) != nullptr ) {
        found = p;
        s = p + 1;
    }

    return (char*)found;
}


__forceinline wchar_t* stub_strrchr( const wchar_t* s, int c )
{
    const wchar_t *found, *p;
    c = (wchar_t)c;

    if ( c == 0 ) {
        return stub_strchr( s, 0 );
    }

    found = nullptr;

    while ( ( p = stub_strchr( s, c ) ) != nullptr ) {
        found = p;
        s = p + 1;
    }

    return (wchar_t*)found;
}

__forceinline char tolower( char c )
{
    if ( c >= 'A' && c <= 'Z' ) {
        return c + 0x20;
    }

    return c;
}

__forceinline wchar_t tolower( wchar_t c )
{
    if ( c >= 'A' && c <= 'Z' ) {
        return c + 0x20;
    }

    return c;
}


__forceinline int stub_strcmp( const char* p1, const char* p2 )
{
    const unsigned char* s1 = (const unsigned char*)p1;
    const unsigned char* s2 = (const unsigned char*)p2;
    unsigned char c1, c2;

    do {
        c1 = *s1++;
        c2 = *s2++;

        if ( c1 == 0 ) {
            return c1 - c2;
        }

    } while ( c1 == c2 );

    return c1 - c2;
}


__forceinline int stub_strcmp( const wchar_t* p1, const wchar_t* p2 )
{
    wchar_t* s1 = (wchar_t*)p1;
    wchar_t* s2 = (wchar_t*)p2;
    wchar_t c1, c2;

    do {
        c1 = *s1++;
        c2 = *s2++;

        if ( c1 == 0 ) {
            return ( ( c1 - c2 ) >> 1 );
        }

    } while ( c1 == c2 );

    return ( ( c1 - c2 ) >> 1 );
}



__forceinline int stub_stricmp( const char* p1, const char* p2 )
{
    const unsigned char* s1 = (const unsigned char*)p1;
    const unsigned char* s2 = (const unsigned char*)p2;
    unsigned char c1, c2;

    do {
        c1 = *s1++;
        c2 = *s2++;

        if ( c1 == 0 ) {
            return c1 - c2;
        }

    } while ( tolower( c1 ) ==  tolower( c2 ) );

    return c1 - c2;
}

__forceinline int stub_stricmp( const wchar_t* p1, const wchar_t* p2 )
{
    wchar_t* s1 = (wchar_t*)p1;
    wchar_t* s2 = (wchar_t*)p2;
    wchar_t c1, c2;

    do {
        c1 = *s1++;
        c2 = *s2++;

        if ( c1 == 0 ) {
            return ( ( c1 - c2 ) >> 1 );
        }

    } while ( tolower( c1 ) == tolower( c2 ) );

    return ( ( c1 - c2 ) >> 1 );
}



__forceinline int stub_strncmp( const char* s1, const char* s2, size_t n )
{
    unsigned char c1 = 0;
    unsigned char c2 = 0;

    while ( n-- ) {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if ( c1 == 0 || c1 != c2 ) {
            return c1 - c2;
        }
    }
    return c1 - c2;
}



__forceinline int stub_strncmp( wchar_t* s1, wchar_t* s2, size_t n )
{
    wchar_t c1 = 0;
    wchar_t c2 = 0;

    while ( n-- ) {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if ( c1 == 0 || c1 != c2 ) {
            return ( ( c1 - c2 ) >> 1 );
        }
    }
    return ( ( c1 - c2 ) >> 1 );
}

