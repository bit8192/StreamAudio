//
// Created by bincker on 2025/7/15.
//

#ifndef DATA_POINTER_H
#define DATA_POINTER_H
#include <cstdint>
#include <vector>

enum ByteOrder {
    LITTLE_ENDIAN,
    BIG_ENDIAN,
};

class DataPointer {
public:
    DataPointer(const uint8_t* raw_pointer, const size_t& size);
    DataPointer(const uint8_t* start, const uint8_t* end);
    explicit DataPointer(const std::vector<uint8_t>& data);

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

private:
    const uint8_t *raw_pointer;
    const uint8_t *raw_pointer_end;
    const size_t size;
    uint8_t *pointer;
    ByteOrder order = BIG_ENDIAN;
    void checkBounds(const size_t& requested) const;
    void copy_with_order(uint8_t* dest, const size_t& size);
    void put_array_with_order(const uint8_t* dest, const size_t& size);
};


#endif //DATA_POINTER_H
