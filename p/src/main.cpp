#include "C:/Users/Shadow/Desktop/p/include/parser.h"
#include <iostream>
#include <fstream>

using namespace std;

void printPEInfo(const string& filePath) {
    ifstream file(filePath, ios::binary);
    if (!file) {
        cerr << "Unable to open file: " << filePath << endl;
        return;
    }

    file.seekg(0, ios::end);
    auto fileSize = file.tellg();
    file.seekg(0, ios::beg);
    auto fileBuffer = new char[fileSize];
    file.read(fileBuffer, fileSize);

    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileBuffer);
    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(fileBuffer + dosHeader->e_lfanew);

    dos(*dosHeader);
    nt(*ntHeaders);
    fileheader(ntHeaders->FileHeader);
    optional(ntHeaders->OptionalHeader);
    sections(*ntHeaders, fileBuffer);
    imports(*ntHeaders, fileBuffer);
    delete[] fileBuffer;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <PE file path>" << endl;
        return 1;
    }

    string filePath = argv[1];
    printPEInfo(filePath);

    return 0;
}
