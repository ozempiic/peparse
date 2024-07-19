#include "C:/Users/Shadow/Desktop/p/include/parser.h"
#include <iostream>

using namespace std;

void dos(const IMAGE_DOS_HEADER& dosHeader) {
    cout << "DOS Header:\n";
    cout << "\t" << hex(dosHeader.e_magic) << "\tMagic number\n";
    cout << "\t" << hex(dosHeader.e_cblp) << "\tBytes on last page of file\n";
    cout << "\t" << hex(dosHeader.e_cp) << "\tPages in file\n";
    cout << "\t" << hex(dosHeader.e_crlc) << "\tRelocations\n";
    cout << "\t" << hex(dosHeader.e_cparhdr) << "\tSize of header in paragraphs\n";
    cout << "\t" << hex(dosHeader.e_minalloc) << "\tMinimum extra paragraphs needed\n";
    cout << "\t" << hex(dosHeader.e_maxalloc) << "\tMaximum extra paragraphs needed\n";
    cout << "\t" << hex(dosHeader.e_ss) << "\tInitial (relative) SS value\n";
    cout << "\t" << hex(dosHeader.e_sp) << "\tInitial SP value\n";
    cout << "\t" << hex(dosHeader.e_csum) << "\tChecksum\n";
    cout << "\t" << hex(dosHeader.e_ip) << "\tInitial IP value\n";
    cout << "\t" << hex(dosHeader.e_cs) << "\tInitial (relative) CS value\n";
    cout << "\t" << hex(dosHeader.e_lfarlc) << "\tFile address of relocation table\n";
    cout << "\t" << hex(dosHeader.e_ovno) << "\tOverlay number\n";
    cout << "\t" << hex(dosHeader.e_oemid) << "\tOEM identifier (for e_oeminfo)\n";
    cout << "\t" << hex(dosHeader.e_oeminfo) << "\tOEM information; e_oemid specific\n";
    cout << "\t" << hex(dosHeader.e_lfanew) << "\tFile address of new exe header\n";
}

void nt(const IMAGE_NT_HEADERS& ntHeaders) {
    cout << "\nNT Headers:\n";
    cout << "\t" << hex(ntHeaders.Signature) << "\tSignature\n";
    cout << "\t" << hex(ntHeaders.FileHeader.Machine) << "\tMachine\n";
    cout << "\t" << hex(ntHeaders.FileHeader.NumberOfSections) << "\tNumber of Sections\n";
    cout << "\t" << hex(ntHeaders.FileHeader.TimeDateStamp) << "\tTime Date Stamp\n";
    cout << "\t" << hex(ntHeaders.FileHeader.PointerToSymbolTable) << "\tPointer to Symbol Table\n";
    cout << "\t" << hex(ntHeaders.FileHeader.NumberOfSymbols) << "\tNumber of Symbols\n";
    cout << "\t" << hex(ntHeaders.FileHeader.SizeOfOptionalHeader) << "\tSize of Optional Header\n";
    cout << "\t" << hex(ntHeaders.FileHeader.Characteristics) << "\tCharacteristics\n";
}

void fileheader(const IMAGE_FILE_HEADER& fileHeader) {
    cout << "\nFile Header:\n";
    cout << "\t" << hex(fileHeader.Machine) << "\tMachine\n";
    cout << "\t" << hex(fileHeader.NumberOfSections) << "\tNumber of Sections\n";
    cout << "\t" << hex(fileHeader.TimeDateStamp) << "\tTime Stamp\n";
    cout << "\t" << hex(fileHeader.PointerToSymbolTable) << "\tPointer to Symbol Table\n";
    cout << "\t" << hex(fileHeader.NumberOfSymbols) << "\tNumber of Symbols\n";
    cout << "\t" << hex(fileHeader.SizeOfOptionalHeader) << "\tSize of Optional Header\n";
    cout << "\t" << hex(fileHeader.Characteristics) << "\tCharacteristics\n";
}

void optional(const IMAGE_OPTIONAL_HEADER& optHeader) {
    cout << "\nOptional Header:\n";
    cout << "\t" << hex(optHeader.Magic) << "\tMagic\n";
    cout << "\t" << hex(optHeader.MajorLinkerVersion) << "\tMajor Linker Version\n";
    cout << "\t" << hex(optHeader.MinorLinkerVersion) << "\tMinor Linker Version\n";
    cout << "\t" << hex(optHeader.SizeOfCode) << "\tSize Of Code\n";
    cout << "\t" << hex(optHeader.SizeOfInitializedData) << "\tSize Of Initialized Data\n";
    cout << "\t" << hex(optHeader.SizeOfUninitializedData) << "\tSize Of Uninitialized Data\n";
    cout << "\t" << hex(optHeader.AddressOfEntryPoint) << "\tAddress Of Entry Point (.text)\n";
    cout << "\t" << hex(optHeader.BaseOfCode) << "\tBase Of Code\n";
    cout << "\t" << hex(optHeader.ImageBase) << "\tImage Base\n";
    cout << "\t" << hex(optHeader.SectionAlignment) << "\tSection Alignment\n";
    cout << "\t" << hex(optHeader.FileAlignment) << "\tFile Alignment\n";
    cout << "\t" << hex(optHeader.MajorOperatingSystemVersion) << "\tMajor Operating System Version\n";
    cout << "\t" << hex(optHeader.MinorOperatingSystemVersion) << "\tMinor Operating System Version\n";
    cout << "\t" << hex(optHeader.MajorImageVersion) << "\tMajor Image Version\n";
    cout << "\t" << hex(optHeader.MinorImageVersion) << "\tMinor Image Version\n";
    cout << "\t" << hex(optHeader.MajorSubsystemVersion) << "\tMajor Subsystem Version\n";
    cout << "\t" << hex(optHeader.MinorSubsystemVersion) << "\tMinor Subsystem Version\n";
    cout << "\t" << hex(optHeader.Win32VersionValue) << "\tWin32 Version Value\n";
    cout << "\t" << hex(optHeader.SizeOfImage) << "\tSize Of Image\n";
    cout << "\t" << hex(optHeader.SizeOfHeaders) << "\tSize Of Headers\n";
    cout << "\t" << hex(optHeader.CheckSum) << "\tCheckSum\n";
    cout << "\t" << hex(optHeader.Subsystem) << "\tSubsystem\n";
    cout << "\t" << hex(optHeader.DllCharacteristics) << "\tDllCharacteristics\n";
    cout << "\t" << hex(optHeader.SizeOfStackReserve) << "\tSize Of Stack Reserve\n";
    cout << "\t" << hex(optHeader.SizeOfStackCommit) << "\tSize Of Stack Commit\n";
    cout << "\t" << hex(optHeader.SizeOfHeapReserve) << "\tSize Of Heap Reserve\n";
    cout << "\t" << hex(optHeader.SizeOfHeapCommit) << "\tSize Of Heap Commit\n";
    cout << "\t" << hex(optHeader.LoaderFlags) << "\tLoader Flags\n";
    cout << "\t" << hex(optHeader.NumberOfRvaAndSizes) << "\tNumber Of Rva And Sizes\n";
}

void sections(const IMAGE_NT_HEADERS& ntHeaders, LPVOID baseAddress) {
    cout << "\nSection Headers:\n";
    auto sectionHeader = IMAGE_FIRST_SECTION(&ntHeaders);

    for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        cout << "\t" << sectionHeader[i].Name << "\n";
        cout << "\t\t" << hex(sectionHeader[i].Misc.VirtualSize) << "\tVirtual Size\n";
        cout << "\t\t" << hex(sectionHeader[i].VirtualAddress) << "\tVirtual Address\n";
        cout << "\t\t" << hex(sectionHeader[i].SizeOfRawData) << "\tSize Of Raw Data\n";
        cout << "\t\t" << hex(sectionHeader[i].PointerToRawData) << "\tPointer To Raw Data\n";
        cout << "\t\t" << hex(sectionHeader[i].PointerToRelocations) << "\tPointer To Relocations\n";
        cout << "\t\t" << hex(sectionHeader[i].PointerToLinenumbers) << "\tPointer To Linenumbers\n";
        cout << "\t\t" << hex(sectionHeader[i].NumberOfRelocations) << "\tNumber Of Relocations\n";
        cout << "\t\t" << hex(sectionHeader[i].NumberOfLinenumbers) << "\tNumber Of Linenumbers\n";
        cout << "\t\t" << hex(sectionHeader[i].Characteristics) << "\tCharacteristics\n";
    }
}

void imports(const IMAGE_NT_HEADERS& ntHeaders, LPVOID baseAddress) {
    cout << "\nImport Table:\n";
    auto importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)baseAddress + ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDesc->Name) {
        auto moduleName = (char*)((BYTE*)baseAddress + importDesc->Name);
        cout << "\t" << moduleName << "\n";

        auto thunk = (IMAGE_THUNK_DATA*)((BYTE*)baseAddress + importDesc->FirstThunk);
        while (thunk->u1.AddressOfData) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                cout << "\t\t" << "Ordinal: " << IMAGE_ORDINAL(thunk->u1.Ordinal) << "\n";
            }
            else {
                auto importName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)baseAddress + (thunk->u1.AddressOfData));
                cout << "\t\t" << importName->Name << "\n";
            }
            ++thunk;
        }
        ++importDesc;
    }
}