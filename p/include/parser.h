#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <Windows.h>
#include <string>

using namespace std;

string hex(DWORD value);

void dos(const IMAGE_DOS_HEADER& dosHeader);
void nt(const IMAGE_NT_HEADERS& ntHeaders);
void fileheader(const IMAGE_FILE_HEADER& fileHeader);
void optional(const IMAGE_OPTIONAL_HEADER& optHeader);
void sections(const IMAGE_NT_HEADERS& ntHeaders, LPVOID baseAddress);
void imports(const IMAGE_NT_HEADERS& ntHeaders, LPVOID baseAddress);

#endif 