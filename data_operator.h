//
// Created by bincker on 2025/7/15.
//

#ifndef DATA_OPERATOR_H
#define DATA_OPERATOR_H
#include <cstdint>
#include <string>
#include <vector>

enum ByteOrder {
    ORDER_LITTLE_ENDIAN,
    ORDER_BIG_ENDIAN,
};

class DataOperator {
public:
    DataOperator(const uint8_t* raw_pointer, const size_t& size);
    DataOperator(const uint8_t* start, const uint8_t* end);
    explicit DataOperator(const std::vector<uint8_t>& data);

    uint8_t get();

    void put(const uint8_t& value);

    uint16_t get_uint16();

    void put_uint16(const uint16_t& value);

    int get_int();

    uint32_t get_uint();

    void put_int(const int& i);

    void put_uint(const uint32_t& i);

    std::vector<uint8_t> get_array(const size_t& size);

    void copy_to(uint8_t* dest, const size_t& size);

    void reverse_copy_to(uint8_t* dest, const size_t& size);

    void put_array(const std::vector<uint8_t>& value);

    void put_array(const uint8_t* start, const size_t& size);

    void put_array_reverse(const std::vector<uint8_t>& value);

    void put_array_reverse(const uint8_t* start, const size_t& size);

    [[nodiscard]] size_t remaining() const;

    [[nodiscard]] size_t position() const;

    void set_order(ByteOrder order);

    [[nodiscard]] std::string to_hex() const;

    void mark();

    void reset();

    void clear();

    void flip();

private:
    const uint8_t *raw_pointer;
    const uint8_t *raw_pointer_end;
    const size_t size;
    uint8_t *pointer;
    uint8_t *limit_pointer;
    uint8_t *mark_pointer = nullptr;
    ByteOrder order = ORDER_BIG_ENDIAN;
    void checkBounds(const size_t& requested) const;
    void copy_with_order(uint8_t* dest, const size_t& size);
    void put_array_with_order(const uint8_t* dest, const size_t& size);
};


#endif //DATA_OPERATOR_H
