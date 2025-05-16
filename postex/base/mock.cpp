#include <iostream>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <utility>
#include <cstring>
#include <map>
#include <Windows.h>

#include "beacon.h"
#include "macros.h"
#include "mock.h"
#include "utils.h"

char* PostexDataPacker::getData() {
    return size() > 0 ? reinterpret_cast<char*>(&data[0]) : nullptr;
}

int PostexDataPacker::size() {
    return data.size();
}

void PostexDataPacker::addData(const char* buf, std::size_t len) {
    RETURN_ON_NULL(buf);
    std::vector<char> bytes;
    bytes.assign(buf, buf + len);
    insert(static_cast<int>(len));
    append(bytes);
}

void PostexDataPacker::append(const std::vector<char>& data) {
    this->data.insert(std::end(this->data), std::begin(data), std::end(data));
}

void PostexDataPacker::insert(int v) {
    append(ToBytes(SwapEndianness(v)));
}

void PostexDataPacker::insert(short v) {
    append(ToBytes(SwapEndianness(v)));
}

void PostexDataPacker::insert(unsigned int v) {
    insert(static_cast<int>(v));
}

void PostexDataPacker::insert(unsigned short v) {
    insert(static_cast<short>(v));
}

void PostexDataPacker::insert(const char* v) {
    addData(v, std::strlen(v) + 1);
}

void PostexDataPacker::insert(const wchar_t* v) {
    addData((const char*)v, (std::wcslen(v) + 1) * sizeof(wchar_t));
}

void PostexDataPacker::insert(const std::vector<char>& data) {
    pack<int32_t>(data.size());
    append(data);
}
