#include <iostream>
#include <string>
#include <array>
#include <Windows.h>
#include <vector>
#include <Psapi.h>

#define SKIP_KEY -1

using namespace std;

template<int size>
struct XorString {

    constexpr __forceinline XorString( const char* str ) {
        crypt( str );
    }
    char key = '$';
    std::array<char, size> decrptValue;

    constexpr __forceinline void crypt( const char* str ) {
        char* cStr = (char*)( str );
        for ( int i = 0; i < size; i++ ) {
            decrptValue [i] = cStr [i] ^ key;
        }
    }
    constexpr __forceinline decltype( auto ) decrypt( ) {

        for ( int i = 0; i < size; i++ ) {
            decrptValue [i] = decrptValue [i] ^ key;
        }

        return decrptValue.data( );
    }

};

std::pair<void*, unsigned long> get_module_info( const char* dll_name ) {
    HMODULE dllHandle = GetModuleHandleA( dll_name );
    if ( dllHandle == INVALID_HANDLE_VALUE ) return std::make_pair( nullptr, 0 );

    MODULEINFO dllInfo = { 0 };


    GetModuleInformation( GetCurrentProcess( ), dllHandle, &dllInfo, sizeof( dllInfo ) );

    return std::make_pair( dllInfo.lpBaseOfDll, dllInfo.SizeOfImage );

}

void* ida_pattern_scan( const char* dll, const char* pattern ) {
    const auto [dllBaseAddress, dllSizeOf] = get_module_info( dll );
    if ( !dllBaseAddress || !dllSizeOf ) return nullptr;

    BYTE* dllBaseStartAddress = (BYTE*)( dllBaseAddress );

    size_t patternLen = strlen( pattern );
    char* start = const_cast<char*>( pattern );
    const char* patternEnd = pattern + patternLen;

    std::vector<int> bytes;

    while ( start <= patternEnd ) {
        if ( *start == '?' ) {
            start++;
            if ( *start == '?' ) {
                start++;
            }
            bytes.push_back( SKIP_KEY );
        }
        else {
            bytes.push_back( strtoul( start, &start, 16 ) );
        }
        start++;
    }

    auto bytesData = bytes.data( );
    auto bytesDataSize = bytes.size( );

    for ( DWORD i = 0; i < dllSizeOf - bytesDataSize; i++ ) {
        bool found = true;
        for ( DWORD j = 0; j < bytesDataSize; j++ ) {
            if ( dllBaseStartAddress [i + j] != bytesData [j] && bytesData [j] != SKIP_KEY ) {
                found = false;
                break;
            }
        }

        if ( found ) {
            return &dllBaseStartAddress [i];
        }
    }

    return nullptr;
}

#define xor_text(str) XorString<sizeof( str )>( str ).decrypt( )

int main()
{
    std::cout << ida_pattern_scan( xor_text("kernelbase.dll"), xor_text("4C 8B DC 53 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 41 8B F9 4D 8B E0 4C 89 44 24 ? 4C 8B F2 48 89 94 24 ? ? ? ?") );
}

