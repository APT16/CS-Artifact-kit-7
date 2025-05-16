#pragma once
#include <vector>
#include <string>

/**
* Data container class used for packing arguments.
*/
class PostexDataPacker {
public:
    /**
    * Pack a variadic number of arguments.
    * Equivalent to the bof_pack function.
    *
    * For example, bof_pack("isz", 1, 2, "hello")
    * -> pack<int, short, const char*>(1, 2, "hello")
    *
    * @param ... arguments
    */
    template <typename... T>
    void pack(T ...v)
    {
        ((insert(std::forward<T>(v))), ...);
    }

    /**
    * Add binary data to the argument buffer.
    * Equivalent to bof_pack("b", $data).
    *
    * @param buf A char pointer to the data
    * @param len A length to the data
    */
    void addData(const char* buf, std::size_t len);

    /**
    * Return a raw argument buffer.
    *
    * @return A char pointer of raw argument buffer
    */
    char* getData();

    /**
    * Get the size of the argument buffer.
    *
    * @return A size of the argument buffer
    */
    int size();

private:
    void append(const std::vector<char>& data);
    void insert(int v);
    void insert(short v);
    void insert(unsigned int v);
    void insert(unsigned short v);
    void insert(const char* v);
    void insert(const wchar_t* v);
    void insert(const std::vector<char>& data);

    std::vector<char> data;
};
