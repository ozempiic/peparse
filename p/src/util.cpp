#include "C:/Users/Shadow/Desktop/p/include/parser.h"
#include <sstream>
#include <iomanip>

string hex(DWORD value) {
    stringstream ss;
    ss << "0x" << hex << setw(8) << setfill('0') << value;
    return ss.str();
}