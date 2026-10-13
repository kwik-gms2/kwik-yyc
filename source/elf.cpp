#include "kwik_yyc/elf.hpp"
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace kwik::yyc {
namespace {
uint16_t u16(const std::vector<uint8_t>& d, size_t o) {
    if (o + 2 > d.size()) throw std::runtime_error("truncated ELF");
    uint16_t v; std::memcpy(&v, d.data()+o, 2); return v;
}
uint32_t u32(const std::vector<uint8_t>& d, size_t o) {
    if (o + 4 > d.size()) throw std::runtime_error("truncated ELF");
    uint32_t v; std::memcpy(&v, d.data()+o, 4); return v;
}
uint64_t u64(const std::vector<uint8_t>& d, size_t o) {
    if (o + 8 > d.size()) throw std::runtime_error("truncated ELF");
    uint64_t v; std::memcpy(&v, d.data()+o, 8); return v;
}
}

ElfImage::ElfImage(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("could not open executable: " + path.string());
    data_ = std::vector<uint8_t>(std::istreambuf_iterator<char>(f), {});
    if (data_.size() < 64 || std::memcmp(data_.data(), "\x7f" "ELF", 4) != 0)
        throw std::runtime_error("input is not an ELF file");
    if (data_[4] != 2 || data_[5] != 1)
        throw std::runtime_error("only little-endian ELF64 is supported in this PoC");
    if (u16(data_, 18) != 62)
        throw std::runtime_error("only x86-64 YYC executables are supported in this PoC");

    entry_ = u64(data_, 24);
    const auto shoff = u64(data_, 40);
    const auto shentsize = u16(data_, 58);
    const auto shnum = u16(data_, 60);
    const auto shstrndx = u16(data_, 62);
    if (shentsize < 64 || shoff + uint64_t(shentsize) * shnum > data_.size())
        throw std::runtime_error("invalid ELF section table");
    if (shstrndx >= shnum) throw std::runtime_error("invalid section string table index");

    const auto shstr = shoff + uint64_t(shentsize) * shstrndx;
    const auto str_off = u64(data_, shstr + 24);
    const auto str_size = u64(data_, shstr + 32);
    if (str_off + str_size > data_.size()) throw std::runtime_error("invalid section name table");

    for (uint16_t i = 0; i < shnum; ++i) {
        const auto s = shoff + uint64_t(shentsize) * i;
        const auto name_off = u32(data_, s);
        std::string name;
        if (name_off < str_size) {
            auto p = str_off + name_off;
            while (p < str_off + str_size && data_[p]) name.push_back(char(data_[p++]));
        }
        Section sec;
        sec.name = std::move(name);
        sec.type = u32(data_, s + 4);
        sec.flags = u64(data_, s + 8);
        sec.address = u64(data_, s + 16);
        sec.offset = u64(data_, s + 24);
        sec.size = u64(data_, s + 32);
        sec.alignment = u64(data_, s + 48);
        sections_.push_back(std::move(sec));
    }
}

std::optional<uint64_t> ElfImage::offset_to_va(uint64_t off) const {
    for (const auto& s : sections_)
        if (s.type != 8 && off >= s.offset && off < s.offset + s.size)
            return s.address + (off - s.offset);
    return std::nullopt;
}
std::optional<uint64_t> ElfImage::va_to_offset(uint64_t va) const {
    for (const auto& s : sections_)
        if (s.type != 8 && va >= s.address && va < s.address + s.size)
            return s.offset + (va - s.address);
    return std::nullopt;
}
bool ElfImage::is_executable_va(uint64_t va) const {
    for (const auto& s : sections_) if (s.executable() && va >= s.address && va < s.address+s.size) return true;
    return false;
}
bool ElfImage::is_allocated_va(uint64_t va) const {
    for (const auto& s : sections_) if (s.allocated() && va >= s.address && va < s.address+s.size) return true;
    return false;
}
bool ElfImage::is_writable_va(uint64_t va) const {
    for (const auto& s : sections_) if (s.writable() && va >= s.address && va < s.address+s.size) return true;
    return false;
}
std::optional<std::string> ElfImage::cstring_at_va(uint64_t va, size_t max) const {
    auto off = va_to_offset(va); if (!off) return std::nullopt;
    std::string out;
    for (size_t i=0; i<max && *off+i<data_.size(); ++i) {
        const auto c=data_[*off+i]; if (!c) return out;
        if (c < 0x20 || c > 0x7e) return std::nullopt;
        out.push_back(char(c));
    }
    return std::nullopt;
}
uint64_t ElfImage::read_u64(uint64_t off) const { return u64(data_, size_t(off)); }
}
