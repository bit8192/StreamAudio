//
// Created by bincker on 2025/7/15.
//

#include "data_pointer.h"
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <cstring>

DataPointer::DataPointer(const uint8_t *raw_pointer, const size_t &size)
    : raw_pointer(raw_pointer),
      raw_pointer_end(raw_pointer + size),
      size(size),
      pointer(const_cast<uint8_t *>(raw_pointer)) {
}

DataPointer::DataPointer(const uint8_t *start, const uint8_t *end)
    : raw_pointer(start),
      raw_pointer_end(end),
      size(end - start),
      pointer(const_cast<uint8_t *>(start)) {
}

DataPointer::DataPointer(const std::vector<uint8_t> &data)
    : raw_pointer(data.data()),
      raw_pointer_end(data.data() + data.size()),
      size(data.size()),
      pointer(const_cast<uint8_t *>(data.data())) {
}

uint8_t DataPointer::get() {
    checkBounds(1);
    return *pointer++;
}

void DataPointer::put(const uint8_t &value) {
    checkBounds(1);
    *pointer++ = value;
}

uint16_t DataPointer::get_uint16() {
    uint16_t value;
    copy_with_order(reinterpret_cast<uint8_t *>(&value), 4);
    return value;
}

void DataPointer::put_uint16(const uint16_t &value) {
    checkBounds(4);
    *pointer++ = static_cast<uint8_t>((value >> 24) & 0xFF);
    *pointer++ = static_cast<uint8_t>((value >> 16) & 0xFF);
    *pointer++ = static_cast<uint8_t>((value >> 8) & 0xFF);
    *pointer++ = static_cast<uint8_t>(value & 0xFF);
}

int DataPointer::get_int() {
    int value;
    copy_to(reinterpret_cast<uint8_t *>(&value), 4);
    return value;
}

uint32_t DataPointer::get_uint() {
    checkBounds(4);
    uint32_t value = 0;
    value |= static_cast<uint32_t>(*pointer++) << 24;
    value |= static_cast<uint32_t>(*pointer++) << 16;
    value |= static_cast<uint32_t>(*pointer++) << 8;
    value |= static_cast<uint32_t>(*pointer++);
    return value;
}

void DataPointer::put_int(const int &i) {
    put_array_with_order(reinterpret_cast<const uint8_t *>(&i), 4);
}

void DataPointer::put_uint(const uint32_t &i) {
    put_array_with_order(reinterpret_cast<const uint8_t *>(&i), 4);
}

std::vector<uint8_t> DataPointer::get_array(const size_t &size) {
    checkBounds(size);
    std::vector result(pointer, pointer + size);
    pointer += size;
    return result;
}

void DataPointer::copy_to(uint8_t *dest, const size_t &size) {
    checkBounds(size);
    std::copy_n(pointer, size, dest);
    pointer += size;
}

void DataPointer::reverse_copy_to(uint8_t* dest, const size_t& size) {
    checkBounds(size);
    std::reverse_copy(pointer, pointer + size, dest);
    pointer += size;
}

void DataPointer::copy_with_order(uint8_t *dest, const size_t &size) {
    if (order == BIG_ENDIAN) {
        reverse_copy_to(dest, size);
    }else {
        copy_to(dest, size);
    }
}

void DataPointer::put_array(const std::vector<uint8_t> &value) {
    put_array(value.data(), static_cast<uint32_t>(value.size()));
}

void DataPointer::put_array(const uint8_t *start, const size_t &size) {
    checkBounds(size);
    std::copy_n(start, size, pointer);
    pointer += size;
}

void DataPointer::put_array_reverse(const std::vector<uint8_t> &value) {
    put_array_reverse(value.data(), static_cast<uint32_t>(value.size()));
}

void DataPointer::put_array_reverse(const uint8_t *start, const size_t &size) {
    checkBounds(size);
    std::reverse_copy(pointer, pointer + size, start);
    pointer += size;
}

size_t DataPointer::remaining() const {
    return raw_pointer_end - pointer;
}

size_t DataPointer::position() const {
    return pointer - raw_pointer;
}

void DataPointer::checkBounds(const size_t &requested) const {
    if (pointer + requested > raw_pointer_end) {
        throw std::out_of_range("Attempt to read/write beyond buffer bounds");
    }
}

void DataPointer::put_array_with_order(const uint8_t *dest, const size_t &size) {
    if (order == BIG_ENDIAN) {
        put_array_reverse(dest, size);
    }else {
        put_array(dest, size);
    }
}

void DataPointer::set_order(const ByteOrder order) {
    this->order = order;
}
