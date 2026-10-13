#pragma once
#include "kwik_yyc/analysis.hpp"
#include "kwik_yyc/elf.hpp"
#include "kwik_yyc/iff.hpp"
#include "kwik_yyc/yyc.hpp"
#include <filesystem>
namespace kwik::yyc {
void emit_project(const std::filesystem::path& out, const std::filesystem::path& exe,
                  const std::filesystem::path& game_data, const ElfImage& elf,
                  const IffInfo& iff, const Discovery& discovery, const CodeAnalysis& analysis);
void emit_manifest(const std::filesystem::path& path, const ElfImage& elf,
                   const IffInfo& iff, const Discovery& discovery, const CodeAnalysis* analysis = nullptr);
void emit_code_analysis(const std::filesystem::path& path, const CodeAnalysis& analysis);
}
