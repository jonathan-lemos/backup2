//
// Created by jonathan on 5/3/20.
//

#include "strings.h"
#include <cstdarg>
#include <vector>
#include <stdexcept>

std::string format(const char *format, ...) {
    va_list ap;

    va_start(ap, format);
    size_t len = vsnprintf(nullptr, 0, format, ap);

    if (len < 0) {
        throw std::runtime_error("Invalid format string");
    }

    va_end(ap);

    std::vector<char> buf(len + 1);

    if (vsnprintf(buf.data(), buf.size(), format, ap) != buf.size()) {
        throw std::runtime_error("Could not create formatted string");
    }

    return buf.data();
}
