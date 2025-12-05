//
// Created by bincker on 2025/7/15.
//

#include "data_operator.h"
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <cstring>

DataOperator::DataOperator(const uint8_t *raw_pointer, const size_t &size)
    : raw_pointer(raw_pointer),
      raw_pointer_end(raw_pointer + size),
      size(size),
      pointer(const_cast<uint8_t *>(raw_pointer)),
      limit_pointer(pointer + size) {
}

DataOperator::DataOperator(const uint8_t *start, const uint8_t *end)
    : raw_pointer(start),
      raw_pointer_end(end),
      size(end - start),
      pointer(const_cast<uint8_t *>(start)),
      limit_pointer(pointer + size) {
}

DataOperator::DataOperator(const std::vector<uint8_t> &data)
    : raw_pointer(data.data()),
      raw_pointer_end(data.data() + data.size()),
      size(data.size()),
      pointer(const_cast<uint8_t *>(data.data())),
      limit_pointer(pointer + size) {
}

uint8_t DataOperator::get() {
    checkBounds(1);
    return *pointer++;
}

void DataOperator::put(const uint8_t &value) {
    checkBounds(1);
    *pointer++ = value;
}

uint16_t DataOperator::get_uint16() {
    uint16_t value;
    copy_with_order(reinterpret_cast<uint8_t *>(&value), 2);
    return value;
}

void DataOperator::put_uint16(const uint16_t &value) {
    checkBounds(2);
    put_array_with_order(reinterpret_cast<const uint8_t *>(value), 2);
}

int DataOperator::get_int() {
    int value;
    copy_with_order(reinterpret_cast<uint8_t *>(&value), 4);
    return value;
}

uint32_t DataOperator::get_uint() {
    checkBounds(4);
    uint32_t value = 0;
    copy_with_order(reinterpret_cast<uint8_t *>(&value), 4);
    return value;
}

void DataOperator::put_int(const int &i) {
    put_array_with_order(reinterpret_cast<const uint8_t *>(&i), 4);
}

void DataOperator::put_uint(const uint32_t &i) {
    put_array_with_order(reinterpret_cast<const uint8_t *>(&i), 4);
}

std::vector<uint8_t> DataOperator::get_array(const size_t &size) {
    checkBounds(size);
    std::vector result(pointer, pointer + size);
    pointer += size;
    return result;
}

void DataOperator::copy_to(uint8_t *dest, const size_t &size) {
    checkBounds(size);
    std::copy_n(pointer, size, dest);
    pointer += size;
}

void DataOperator::reverse_copy_to(uint8_t* dest, const size_t& size) {
    checkBounds(size);
    std::reverse_copy(pointer, pointer + size, dest);
    pointer += size;
}

void DataOperator::copy_with_order(uint8_t *dest, const size_t &size) {
    if (order == ORDER_BIG_ENDIAN) {
        reverse_copy_to(dest, size);
    }else {
        copy_to(dest, size);
    }
}

void DataOperator::put_array(const std::vector<uint8_t> &value) {
    put_array(value.data(), static_cast<uint32_t>(value.size()));
}

void DataOperator::put_array(const uint8_t *start, const size_t &size) {
    checkBounds(size);
    std::copy_n(start, size, pointer);
    pointer += size;
}

void DataOperator::put_array_reverse(const std::vector<uint8_t> &value) {
    put_array_reverse(value.data(), static_cast<uint32_t>(value.size()));
}

void DataOperator::put_array_reverse(const uint8_t *start, const size_t &size) {
    checkBounds(size);
    std::reverse_copy(start, start + size, pointer);
    pointer += size;
}

size_t DataOperator::remaining() const {
    return limit_pointer - pointer;
}

size_t DataOperator::position() const {
    return pointer - raw_pointer;
}

void DataOperator::checkBounds(const size_t &requested) const {
    if (pointer + requested > limit_pointer) {
        throw std::out_of_range("Attempt to read/write beyond buffer bounds");
    }
}

void DataOperator::put_array_with_order(const uint8_t *dest, const size_t &size) {
    if (order == ORDER_BIG_ENDIAN) {
        put_array_reverse(dest, size);
    }else {
        put_array(dest, size);
    }
}

void DataOperator::set_order(const ByteOrder order) {
    this->order = order;
}

std::string DataOperator::to_hex() const {
    char hex[size * 2 + 1];
    hex[size * 2] = 0;
    for (int i = 0; i < size; ++i) {
        sprintf(&hex[i * 2], "%02x", raw_pointer[i]);
    }
    return hex;
}

void DataOperator::mark() {
    mark_pointer = pointer;
}

void DataOperator::reset() {
    if (mark_pointer == nullptr) return;
    pointer = mark_pointer;
}

void DataOperator::clear() {
    pointer = const_cast<uint8_t *>(raw_pointer);
    mark_pointer = nullptr;
    limit_pointer = const_cast<uint8_t *>(raw_pointer_end);
}

void DataOperator::flip() {
    limit_pointer = pointer;
    pointer = const_cast<uint8_t *>(raw_pointer);
}
