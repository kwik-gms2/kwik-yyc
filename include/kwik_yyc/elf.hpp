#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace kwik::yyc {
struct Section {
    std::string name;
    uint64_t type{};
    uint64_t flags{};
    uint64_t address{};
    uint64_t offset{};
    uint64_t size{};
    uint64_t alignment{};
    bool executable() const { return (flags & 0x4) != 0; }
    bool writable() const { return (flags & 0x1) != 0; }
    bool allocated() const { return (flags & 0x2) != 0; }
};

class ElfImage {
public:
    explicit ElfImage(const std::filesystem::path& path);
    const std::vector<uint8_t>& bytes() const { return data_; }
    const std::vector<Section>& sections() const { return sections_; }
    uint64_t entry() const { return entry_; }
    std::optional<uint64_t> offset_to_va(uint64_t off) const;
    std::optional<uint64_t> va_to_offset(uint64_t va) const;
    bool is_executable_va(uint64_t va) const;
    bool is_allocated_va(uint64_t va) const;
    bool is_writable_va(uint64_t va) const;
    std::optional<std::string> cstring_at_va(uint64_t va, size_t max = 4096) const;
    uint64_t read_u64(uint64_t file_offset) const;
private:
    std::vector<uint8_t> data_;
    std::vector<Section> sections_;
    uint64_t entry_{};
};
}
