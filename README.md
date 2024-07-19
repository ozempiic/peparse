# PE Parser

pls dont bully :( ik its bad

## Overview

- **DOS Header**: Displays information about the DOS header of the PE file.
- **NT Headers**: Shows details about the NT headers, including the file header and optional header.
- **File Header**: Provides information from the IMAGE_FILE_HEADER structure.
- **Optional Header**: Displays information from the IMAGE_OPTIONAL_HEADER structure.
- **Section Headers**: Lists the details of each section in the PE file.
- **Import Addresses**: Shows the import addresses and imported functions. (currently kinda doesnt work erm)

## How to Build

1. Ensure you have a C++ compiler and Windows SDK installed.
2. Save the provided source code files in the same directory.
3. Open a command prompt and navigate to the directory containing the source code.
4. Compile the program using the following command:

   ```g++ -o parser.exe main.cpp parser.cpp util.cpp```

## Usage

when compiled do this.

```> parser.exe <full pe file path>```

## references
- [tried recreating :/](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++#context)
