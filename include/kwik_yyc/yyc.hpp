#pragma once
#include "kwik_yyc/elf.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace kwik::yyc {
enum class GmlKind { Script, ObjectEvent, Room, Other };
struct GmlFunction {
    std::string name;
    uint64_t name_va{};
    uint64_t function_va{};
    uint64_t metadata_va{};
    uint64_t table_offset{};
    GmlKind kind{GmlKind::Other};
};
struct Discovery {
    std::vector<GmlFunction> functions;
    uint64_t table_begin_offset{};
    uint64_t table_end_offset{};
};
Discovery discover_yyc_functions(const ElfImage& elf);
const char* kind_name(GmlKind kind);
}
