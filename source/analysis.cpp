#include "kwik_yyc/analysis.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cmath>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <iomanip>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>

namespace kwik::yyc {
namespace {
uint32_t read_u32(const std::vector<uint8_t>& d, uint64_t o) {
    if (o + 4 > d.size()) throw std::runtime_error("truncated read");
    uint32_t v;
    std::memcpy(&v, d.data() + o, 4);
    return v;
}

int32_t read_i32(const std::vector<uint8_t>& d, uint64_t o) {
    if (o + 4 > d.size()) throw std::runtime_error("truncated read");
    int32_t v;
    std::memcpy(&v, d.data() + o, 4);
    return v;
}

std::string trim(std::string s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

bool ascii_name(const std::string& s) {
    if (s.empty() || s.size() > 256) return false;
    for (unsigned char c : s) {
        if (c < 0x20 || c > 0x7e) return false;
    }
    return true;
}

std::string shell_quote(const std::string& s) {
    std::string o = "'";
    for (char c : s) {
        if (c == '\'') o += "'\\''";
        else o += c;
    }
    o += "'";
    return o;
}

uint64_t parse_hex(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    if (s.starts_with("0x")) s.remove_prefix(2);
    uint64_t v = 0;
    auto r = std::from_chars(s.data(), s.data() + s.size(), v, 16);
    if (r.ec != std::errc{}) return 0;
    return v;
}

std::vector<Instruction> disassemble_range(const std::filesystem::path& executable, uint64_t start, uint64_t end) {
    const char* env = std::getenv("KWIK_YYC_OBJDUMP");
    const std::string objdump = env && *env ? env : "objdump";
    std::ostringstream cmd;
    cmd << shell_quote(objdump) << " -d -M intel --no-show-raw-insn --start-address=0x" << std::hex << start
        << " --stop-address=0x" << end << " " << shell_quote(executable.string()) << " 2>/dev/null";
    FILE* p = popen(cmd.str().c_str(), "r");
    if (!p) throw std::runtime_error("failed to run objdump");
    std::vector<Instruction> out;
    std::array<char, 8192> buf{};
    std::regex line_re(R"(^\s*([0-9a-fA-F]+):\s*([^\s]+)\s*(.*?)\s*$)");
    std::regex ref_re(R"(#\s*([0-9a-fA-F]+))");
    std::regex branch_re(R"(^\s*([0-9a-fA-F]+))");
    while (std::fgets(buf.data(), static_cast<int>(buf.size()), p)) {
        std::string line(buf.data());
        std::smatch m;
        if (!std::regex_match(line, m, line_re)) continue;
        Instruction ins;
        ins.address = parse_hex(m[1].str());
        ins.mnemonic = m[2].str();
        ins.operands = trim(m[3].str());
        ins.text = trim(ins.mnemonic + (ins.operands.empty() ? "" : " " + ins.operands));
        std::smatch r;
        if (std::regex_search(ins.operands, r, ref_re)) {
            ins.referenced_va = parse_hex(r[1].str());
            ins.has_referenced_va = true;
        }
        if (ins.mnemonic == "call" || ins.mnemonic == "callq" || ins.mnemonic == "jmp" || ins.mnemonic == "jmpq" ||
            (!ins.mnemonic.empty() && ins.mnemonic[0] == 'j')) {
            std::smatch b;
            if (std::regex_search(ins.operands, b, branch_re)) {
                ins.branch_target = parse_hex(b[1].str());
                ins.has_branch_target = true;
            }
        }
        if (ins.address >= start && ins.address < end) out.push_back(std::move(ins));
    }
    const int rc = pclose(p);
    if (rc != 0 && out.empty()) throw std::runtime_error("objdump failed; install binutils or set KWIK_YYC_OBJDUMP");
    return out;
}

bool is_conditional_jump(const std::string& m) {
    return !m.empty() && m[0] == 'j' && m != "jmp" && m != "jmpq";
}

bool is_terminal(const Instruction& i) {
    return i.mnemonic == "ret" || i.mnemonic == "retq" || i.mnemonic == "ud2" || i.mnemonic == "hlt";
}

std::vector<BasicBlock> build_cfg(const std::vector<Instruction>& ins, uint64_t start, uint64_t end) {
    if (ins.empty()) return {};
    std::set<uint64_t> leaders{start};
    for (size_t i = 0; i < ins.size(); ++i) {
        const auto& x = ins[i];
        if (x.has_branch_target && x.branch_target >= start && x.branch_target < end) leaders.insert(x.branch_target);
        if ((x.mnemonic == "jmp" || x.mnemonic == "jmpq" || is_conditional_jump(x.mnemonic) || is_terminal(x)) && i + 1 < ins.size())
            leaders.insert(ins[i + 1].address);
    }
    std::vector<uint64_t> ls(leaders.begin(), leaders.end());
    std::vector<BasicBlock> blocks;
    for (size_t n = 0; n < ls.size(); ++n) {
        const uint64_t bs = ls[n];
        const uint64_t be = n + 1 < ls.size() ? ls[n + 1] : end;
        auto first = std::lower_bound(ins.begin(), ins.end(), bs, [](const Instruction& a, uint64_t v){ return a.address < v; });
        auto last = std::lower_bound(ins.begin(), ins.end(), be, [](const Instruction& a, uint64_t v){ return a.address < v; });
        if (first == last) continue;
        BasicBlock b;
        b.start = bs;
        b.end = last == ins.end() ? end : last->address;
        const auto& tail = *(last - 1);
        if ((tail.mnemonic == "jmp" || tail.mnemonic == "jmpq") && tail.has_branch_target) {
            if (tail.branch_target >= start && tail.branch_target < end) b.successors.push_back(tail.branch_target);
        } else if (is_conditional_jump(tail.mnemonic)) {
            if (tail.has_branch_target && tail.branch_target >= start && tail.branch_target < end) b.successors.push_back(tail.branch_target);
            if (last != ins.end() && last->address < end) b.successors.push_back(last->address);
        } else if (!is_terminal(tail)) {
            if (last != ins.end() && last->address < end) b.successors.push_back(last->address);
        }
        std::sort(b.successors.begin(), b.successors.end());
        b.successors.erase(std::unique(b.successors.begin(), b.successors.end()), b.successors.end());
        blocks.push_back(std::move(b));
    }
    return blocks;
}

struct BitDomInfo {
    std::vector<uint64_t> nodes;
    std::unordered_map<uint64_t, size_t> index;
    std::vector<std::vector<uint64_t>> bits;
    uint64_t virtual_exit{UINT64_MAX};
    size_t words{};
};

static std::vector<uint64_t> full_bits(size_t words, size_t count) {
    std::vector<uint64_t> out(words, ~uint64_t{0});
    if (words && (count & 63)) out.back() = (uint64_t{1} << (count & 63)) - 1;
    return out;
}

static bool bit_has(const BitDomInfo& info, size_t row, uint64_t node) {
    auto it = info.index.find(node);
    if (it == info.index.end()) return false;
    const size_t n = it->second;
    return (info.bits[row][n >> 6] >> (n & 63)) & 1;
}

static size_t bit_count(const std::vector<uint64_t>& bits) {
    size_t out = 0;
    for (auto x : bits) out += static_cast<size_t>(__builtin_popcountll(x));
    return out;
}

BitDomInfo compute_postdominators(const std::vector<BasicBlock>& blocks) {
    BitDomInfo info;
    if (blocks.empty()) return info;
    info.nodes.reserve(blocks.size() + 1);
    for (const auto& b : blocks) info.nodes.push_back(b.start);
    info.nodes.push_back(info.virtual_exit);
    for (size_t i = 0; i < info.nodes.size(); ++i) info.index[info.nodes[i]] = i;
    info.words = (info.nodes.size() + 63) / 64;

    std::vector<std::vector<size_t>> succ(info.nodes.size());
    for (const auto& b : blocks) {
        const size_t bi = info.index[b.start];
        for (auto x : b.successors) {
            auto it = info.index.find(x);
            if (it != info.index.end()) succ[bi].push_back(it->second);
        }
        if (succ[bi].empty()) succ[bi].push_back(info.index[info.virtual_exit]);
    }

    info.bits.assign(info.nodes.size(), full_bits(info.words, info.nodes.size()));
    const size_t exit_i = info.index[info.virtual_exit];
    std::fill(info.bits[exit_i].begin(), info.bits[exit_i].end(), 0);
    info.bits[exit_i][exit_i >> 6] |= uint64_t{1} << (exit_i & 63);

    std::vector<uint64_t> next(info.words);
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& b : blocks) {
            const size_t bi = info.index[b.start];
            bool first = true;
            for (size_t si : succ[bi]) {
                if (first) { next = info.bits[si]; first = false; }
                else for (size_t w = 0; w < info.words; ++w) next[w] &= info.bits[si][w];
            }
            if (first) std::fill(next.begin(), next.end(), 0);
            next[bi >> 6] |= uint64_t{1} << (bi & 63);
            if (next != info.bits[bi]) { info.bits[bi] = next; changed = true; }
        }
    }
    return info;
}

uint64_t nearest_common_postdominator(const BitDomInfo& pd, const std::vector<uint64_t>& entries) {
    if (entries.empty() || pd.nodes.empty()) return 0;
    std::vector<uint64_t> common(pd.words, 0);
    bool first = true;
    for (auto e : entries) {
        auto it = pd.index.find(e);
        if (it == pd.index.end()) return 0;
        if (first) { common = pd.bits[it->second]; first = false; }
        else for (size_t w = 0; w < pd.words; ++w) common[w] &= pd.bits[it->second][w];
    }
    auto exit_it = pd.index.find(pd.virtual_exit);
    if (exit_it != pd.index.end()) common[exit_it->second >> 6] &= ~(uint64_t{1} << (exit_it->second & 63));

    uint64_t best = 0;
    size_t best_depth = 0;
    for (size_t i = 0; i < pd.nodes.size(); ++i) {
        if (!((common[i >> 6] >> (i & 63)) & 1)) continue;
        const size_t depth = bit_count(pd.bits[i]);
        if (!best || depth > best_depth) { best = pd.nodes[i]; best_depth = depth; }
    }
    return best;
}

std::vector<uint64_t> region_until_join(const std::vector<BasicBlock>& blocks, uint64_t entry, uint64_t join) {
    std::unordered_map<uint64_t, const BasicBlock*> by_start;
    for (const auto& b : blocks) by_start[b.start] = &b;
    if (!by_start.contains(entry) || entry == join) return {};
    std::vector<uint64_t> out;
    std::set<uint64_t> seen;
    std::vector<uint64_t> stack{entry};
    while (!stack.empty()) {
        const auto n = stack.back(); stack.pop_back();
        if (n == join || seen.contains(n)) continue;
        auto it = by_start.find(n);
        if (it == by_start.end()) continue;
        seen.insert(n);
        out.push_back(n);
        for (auto s : it->second->successors) if (s != join && !seen.contains(s)) stack.push_back(s);
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<StructuredIfRegion> recover_structured_ifs(const FunctionAnalysis& fn) {
    std::vector<StructuredIfRegion> out;
    const auto pd = compute_postdominators(fn.blocks);
    auto add = [&](uint64_t branch_va, uint64_t t, uint64_t f) {
        if (!t || !f || t == f) return;
        const uint64_t join = nearest_common_postdominator(pd, {t, f});
        if (!join) return;
        StructuredIfRegion r;
        r.branch_va = branch_va; r.true_entry = t; r.false_entry = f; r.join = join;
        r.true_blocks = region_until_join(fn.blocks, t, join);
        r.false_blocks = region_until_join(fn.blocks, f, join);
        out.push_back(std::move(r));
    };
    for (const auto& b : fn.truthy_branches) add(b.branch_va, b.true_target, b.false_target);
    for (const auto& b : fn.builtin_truthy_branches) add(b.branch_va, b.true_target, b.false_target);
    for (const auto& b : fn.expression_branches) add(b.branch_va, b.true_target, b.false_target);
    for (const auto& b : fn.equality_branches) add(b.branch_va, b.true_target, b.false_target);
    for (const auto& b : fn.relational_branches) add(b.branch_va, b.true_target, b.false_target);
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b){ return a.branch_va < b.branch_va; });
    out.erase(std::unique(out.begin(), out.end(), [](const auto& a,const auto& b){return a.branch_va==b.branch_va;}), out.end());
    return out;
}

std::vector<StructuredSwitchRegion> recover_structured_switches(const FunctionAnalysis& fn) {
    std::vector<StructuredSwitchRegion> out;
    const auto pd = compute_postdominators(fn.blocks);
    for (const auto& sw : fn.switches) {
        std::vector<uint64_t> entries;
        for (const auto& c : sw.cases) if (c.target) entries.push_back(c.target);
        if (sw.default_target) entries.push_back(sw.default_target);
        const uint64_t join = nearest_common_postdominator(pd, entries);
        if (!join) continue;
        StructuredSwitchRegion r;
        r.variable = sw.variable; r.scope = sw.scope; r.dispatch_va = sw.dispatch_va; r.join = join;
        r.default_entry = sw.default_target;
        if (r.default_entry) r.default_blocks = region_until_join(fn.blocks, r.default_entry, join);
        for (const auto& c : sw.cases) {
            StructuredSwitchCaseRegion cr;
            cr.value = c.value; cr.entry = c.target; cr.blocks = region_until_join(fn.blocks, c.target, join);
            r.cases.push_back(std::move(cr));
        }
        out.push_back(std::move(r));
    }
    return out;
}

BitDomInfo compute_dominators(const std::vector<BasicBlock>& blocks) {
    BitDomInfo info;
    if (blocks.empty()) return info;
    info.nodes.reserve(blocks.size());
    for (const auto& b : blocks) info.nodes.push_back(b.start);
    for (size_t i = 0; i < info.nodes.size(); ++i) info.index[info.nodes[i]] = i;
    info.words = (info.nodes.size() + 63) / 64;

    std::vector<std::vector<size_t>> pred(info.nodes.size());
    for (const auto& b : blocks) {
        for (auto s : b.successors) {
            auto it = info.index.find(s);
            if (it != info.index.end()) pred[it->second].push_back(info.index[b.start]);
        }
    }
    const size_t entry = 0;
    info.bits.assign(info.nodes.size(), full_bits(info.words, info.nodes.size()));
    std::fill(info.bits[entry].begin(), info.bits[entry].end(), 0);
    info.bits[entry][entry >> 6] |= uint64_t{1} << (entry & 63);

    std::vector<uint64_t> next(info.words);
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t ni = 1; ni < info.nodes.size(); ++ni) {
            bool first = true;
            for (size_t pi : pred[ni]) {
                if (first) { next = info.bits[pi]; first = false; }
                else for (size_t w = 0; w < info.words; ++w) next[w] &= info.bits[pi][w];
            }
            if (first) std::fill(next.begin(), next.end(), 0);
            next[ni >> 6] |= uint64_t{1} << (ni & 63);
            if (next != info.bits[ni]) { info.bits[ni] = next; changed = true; }
        }
    }
    return info;
}

uint64_t branch_va_for_block(const FunctionAnalysis& fn, uint64_t block_start) {
    const BasicBlock* block = nullptr;
    for (const auto& b : fn.blocks) if (b.start == block_start) { block = &b; break; }
    if (!block) return 0;
    uint64_t result = 0;
    for (const auto& ins : fn.instructions) {
        if (ins.address < block->start || ins.address >= block->end) continue;
        if (is_conditional_jump(ins.mnemonic)) result = ins.address;
    }
    return result;
}

std::optional<std::pair<uint64_t,uint64_t>> semantic_targets(const FunctionAnalysis& fn, uint64_t branch_va) {
    for (const auto& b : fn.truthy_branches) if (b.branch_va == branch_va) return {{b.true_target,b.false_target}};
    for (const auto& b : fn.builtin_truthy_branches) if (b.branch_va == branch_va) return {{b.true_target,b.false_target}};
    for (const auto& b : fn.expression_branches) if (b.branch_va == branch_va) return {{b.true_target,b.false_target}};
    for (const auto& b : fn.equality_branches) if (b.branch_va == branch_va) return {{b.true_target,b.false_target}};
    for (const auto& b : fn.relational_branches) if (b.branch_va == branch_va) return {{b.true_target,b.false_target}};
    return std::nullopt;
}

std::vector<StructuredLoopRegion> recover_structured_loops(const FunctionAnalysis& fn) {
    std::vector<StructuredLoopRegion> out;
    if (fn.blocks.empty()) return out;
    const auto dom = compute_dominators(fn.blocks);
    std::unordered_map<uint64_t,const BasicBlock*> by_start;
    std::unordered_map<uint64_t,std::vector<uint64_t>> pred;
    for (const auto& b : fn.blocks) by_start[b.start] = &b;
    for (const auto& b : fn.blocks) for (auto s : b.successors) if (by_start.contains(s)) pred[s].push_back(b.start);

    for (const auto& tail : fn.blocks) {
        for (auto header : tail.successors) {
            auto dit = dom.index.find(tail.start);
            if (dit == dom.index.end() || !bit_has(dom, dit->second, header)) continue;
            std::set<uint64_t> nodes{header,tail.start};
            std::vector<uint64_t> stack{tail.start};
            while (!stack.empty()) {
                const auto n = stack.back(); stack.pop_back();
                for (auto p : pred[n]) if (!nodes.contains(p)) { nodes.insert(p); if (p != header) stack.push_back(p); }
            }
            StructuredLoopRegion r; r.header=header; r.latch=tail.start;
            r.blocks.assign(nodes.begin(),nodes.end());

            auto classify_conditional = [&](uint64_t block_start) -> bool {
                auto bit=by_start.find(block_start); if(bit==by_start.end()||bit->second->successors.size()!=2) return false;
                const uint64_t bva=branch_va_for_block(fn,block_start); if(!bva) return false;
                auto st=semantic_targets(fn,bva); if(!st) return false;
                const bool t_in=nodes.contains(st->first), f_in=nodes.contains(st->second);
                if(t_in==f_in) return false;
                r.branch_va=bva; r.condition_true_enters=t_in;
                r.body_entry=t_in?st->first:st->second; r.exit=t_in?st->second:st->first;
                return true;
            };
            if (!classify_conditional(header)) classify_conditional(tail.start);
            if (!r.branch_va || !r.exit) continue;

            for (auto n : nodes) {
                auto bit=by_start.find(n); if(bit==by_start.end()) continue;
                for (auto s : bit->second->successors) {
                    if (s == r.exit && n != header && n != tail.start) r.break_blocks.push_back(n);
                    if (s == header && n != tail.start) r.continue_blocks.push_back(n);
                }
            }
            std::sort(r.break_blocks.begin(),r.break_blocks.end()); r.break_blocks.erase(std::unique(r.break_blocks.begin(),r.break_blocks.end()),r.break_blocks.end());
            std::sort(r.continue_blocks.begin(),r.continue_blocks.end()); r.continue_blocks.erase(std::unique(r.continue_blocks.begin(),r.continue_blocks.end()),r.continue_blocks.end());
            out.push_back(std::move(r));
        }
    }
    std::sort(out.begin(),out.end(),[](const auto&a,const auto&b){ if(a.header!=b.header)return a.header<b.header;return a.latch<b.latch;});
    out.erase(std::unique(out.begin(),out.end(),[](const auto&a,const auto&b){return a.header==b.header&&a.latch==b.latch;}),out.end());
    return out;
}

std::vector<ShortCircuitRegion> recover_short_circuits(const FunctionAnalysis& fn) {
    std::vector<ShortCircuitRegion> out;
    std::unordered_map<uint64_t,const StructuredIfRegion*> if_by_block;
    for (const auto& r : fn.structured_ifs) {
        uint64_t b=0; for (const auto& bb : fn.blocks) if (r.branch_va >= bb.start && r.branch_va < bb.end) { b=bb.start; break; }
        if (b) if_by_block[b]=&r;
    }
    for (const auto& a : fn.structured_ifs) {
        const StructuredIfRegion* b=nullptr;
        std::string op;

        auto it=if_by_block.find(a.true_entry);
        if(it!=if_by_block.end() && it->second->join==a.join && a.false_entry==a.join && it->second->false_entry==a.false_entry) { b=it->second; op="&&"; }

        if(!b) { it=if_by_block.find(a.false_entry); if(it!=if_by_block.end() && it->second->join==a.join && a.true_entry==it->second->true_entry) { b=it->second; op="||"; } }
        if(!b) continue;
        ShortCircuitRegion r; r.first_branch_va=a.branch_va; r.second_branch_va=b->branch_va; r.op=op; r.join=a.join;
        if(op=="&&") { r.true_entry=b->true_entry; r.false_entry=a.false_entry; }
        else { r.true_entry=a.true_entry; r.false_entry=b->false_entry; }
        out.push_back(std::move(r));
    }
    std::sort(out.begin(),out.end(),[](const auto&a,const auto&b){return a.first_branch_va<b.first_branch_va;});
    out.erase(std::unique(out.begin(),out.end(),[](const auto&a,const auto&b){return a.first_branch_va==b.first_branch_va&&a.second_branch_va==b.second_branch_va;}),out.end());
    return out;
}

std::vector<ConstantAssignment> recover_constant_assignments(
    const std::vector<Instruction>& ins,
    const std::unordered_map<uint64_t, std::string>& variables) {
    std::vector<ConstantAssignment> out;
    for (size_t i = 0; i < ins.size(); ++i) {
        const auto& x = ins[i];
        if (x.mnemonic != "mov" || x.operands.rfind("esi,DWORD PTR [rip+", 0) != 0 || !x.has_referenced_va) continue;
        auto vit = variables.find(x.referenced_va);
        if (vit == variables.end()) continue;
        bool got_ptr = false;
        for (size_t j = i + 1; j < ins.size() && j <= i + 16; ++j) {
            if ((ins[j].mnemonic == "call" || ins[j].mnemonic == "callq") && ins[j].operands == "rax") got_ptr = true;
            if (!got_ptr) continue;
            if (ins[j].mnemonic == "mov" && (ins[j].operands == "QWORD PTR [rbx],0x0" || ins[j].operands == "QWORD PTR [r14],0x0" || ins[j].operands == "QWORD PTR [r15],0x0")) {
                out.push_back({x.address, vit->second, 0.0});
                break;
            }
            if (ins[j].mnemonic == "movabs" && ins[j].operands.rfind("rax,0x", 0) == 0) {
                const auto imm = parse_hex(ins[j].operands.substr(4));
                for (size_t k = j + 1; k < ins.size() && k <= j + 4; ++k) {
                    if (ins[k].mnemonic == "mov" && (ins[k].operands == "QWORD PTR [rbx],rax" || ins[k].operands == "QWORD PTR [r14],rax" || ins[k].operands == "QWORD PTR [r15],rax")) {
                        const double v = std::bit_cast<double>(imm);
                        if (std::isfinite(v)) out.push_back({x.address, vit->second, v});
                        k = ins.size();
                        break;
                    }
                }
                break;
            }
        }
    }
    return out;
}

std::vector<BooleanAssignment> recover_boolean_assignments(
    const std::vector<Instruction>& ins,
    const std::unordered_map<uint64_t, std::string>& variables) {
    std::vector<BooleanAssignment> out;
    static const std::regex stack_type_re(R"(^DWORD PTR \[rsp\+0x([0-9a-fA-F]+)\],0xd$)");
    static const std::regex stack_zero_re(R"(^QWORD PTR \[rsp(?:\+0x([0-9a-fA-F]+))?\],0x0$)");
    static const std::regex stack_reg_re(R"(^QWORD PTR \[rsp(?:\+0x([0-9a-fA-F]+))?\],([a-z0-9]+)$)");
    static const std::regex movabs_one_re(R"(^([a-z0-9]+),0x3ff0000000000000$)");
    for (size_t i = 0; i < ins.size(); ++i) {
        const auto& x = ins[i];
        if (x.mnemonic != "mov" || x.operands.rfind("esi,DWORD PTR [rip+", 0) != 0 || !x.has_referenced_va) continue;
        auto vit = variables.find(x.referenced_va);
        if (vit == variables.end()) continue;

        bool getter_seen = false;
        for (size_t j = i + 1; j < ins.size() && j <= i + 14; ++j) {
            if ((ins[j].mnemonic == "call" || ins[j].mnemonic == "callq") && ins[j].operands == "rax") getter_seen = true;
            if (!getter_seen) continue;

            std::smatch tm;
            if (ins[j].mnemonic != "mov" || !std::regex_match(ins[j].operands, tm, stack_type_re)) continue;
            const uint64_t type_off = parse_hex(tm[1].str());
            if (type_off < 12) continue;
            const uint64_t payload_off = type_off - 12;

            bool found = false;
            bool value = false;
            std::unordered_map<std::string, bool> one_regs;
            for (size_t k = j + 1; k < ins.size() && k <= j + 8; ++k) {
                std::smatch om;
                if (ins[k].mnemonic == "movabs" && std::regex_match(ins[k].operands, om, movabs_one_re)) {
                    one_regs[om[1].str()] = true;
                    continue;
                }
                std::smatch zm;
                if (ins[k].mnemonic == "mov" && std::regex_match(ins[k].operands, zm, stack_zero_re)) {
                    if ((zm[1].matched ? parse_hex(zm[1].str()) : 0) == payload_off) { value = false; found = true; break; }
                }
                std::smatch rm;
                if (ins[k].mnemonic == "mov" && std::regex_match(ins[k].operands, rm, stack_reg_re)) {
                    if ((rm[1].matched ? parse_hex(rm[1].str()) : 0) == payload_off && one_regs.contains(rm[2].str())) { value = true; found = true; break; }
                }
            }
            if (found) out.push_back({x.address, vit->second, value});
            break;
        }
    }
    return out;
}

struct AccessSite {
    size_t id_index{};
    size_t call_index{};
    std::string variable;
    uint64_t id_va{};
    VariableScope scope{VariableScope::Unknown};
    bool write{};
};

bool split_mov_operands(const std::string& ops, std::string& dst, std::string& src) {
    const auto c = ops.find(',');
    if (c == std::string::npos) return false;
    dst = trim(ops.substr(0, c));
    src = trim(ops.substr(c + 1));
    const auto hash = src.find('#');
    if (hash != std::string::npos) src = trim(src.substr(0, hash));
    return true;
}

bool is_reg_name(const std::string& s) {
    static const std::set<std::string> regs = {
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"
    };
    return regs.contains(s);
}

std::optional<uint64_t> rsp_slot(const std::string& op) {
    static const std::regex re(R"(^(?:QWORD PTR )?\[rsp(?:\+0x([0-9a-fA-F]+))?\]$)");
    std::smatch m;
    if (!std::regex_match(op, m, re)) return std::nullopt;
    return m[1].matched ? std::optional<uint64_t>(parse_hex(m[1].str())) : std::optional<uint64_t>(0);
}

std::vector<AccessSite> recover_access_sites(
    const std::vector<Instruction>& ins,
    const std::unordered_map<uint64_t, std::string>& variables) {
    std::vector<AccessSite> out;
    std::unordered_map<std::string, VariableScope> reg;
    std::unordered_map<uint64_t, VariableScope> stack;
    reg["rdi"] = VariableScope::Self;
    reg["rsi"] = VariableScope::Other;

    struct Pending { size_t index{}; uint64_t id_va{}; std::string name; bool valid{}; } pending;
    int accessor_offset = 0;

    for (size_t i = 0; i < ins.size(); ++i) {
        const auto& x = ins[i];
        if (x.mnemonic == "mov") {
            std::string dst, src;
            if (split_mov_operands(x.operands, dst, src)) {
                if (dst == "esi" && x.has_referenced_va) {
                    auto it = variables.find(x.referenced_va);
                    if (it != variables.end()) pending = {i, x.referenced_va, it->second, true};
                }

                auto dslot = rsp_slot(dst);
                auto sslot = rsp_slot(src);
                if (dslot && is_reg_name(src)) {
                    auto it = reg.find(src);
                    if (it != reg.end()) stack[*dslot] = it->second;
                    else stack.erase(*dslot);
                } else if (is_reg_name(dst) && sslot) {
                    auto it = stack.find(*sslot);
                    if (it != stack.end()) reg[dst] = it->second;
                    else reg.erase(dst);
                } else if (is_reg_name(dst) && is_reg_name(src)) {
                    auto it = reg.find(src);
                    if (it != reg.end()) reg[dst] = it->second;
                    else reg.erase(dst);
                } else if (is_reg_name(dst) && src.rfind("QWORD PTR [rip+", 0) == 0) {
                    reg[dst] = VariableScope::Global;
                } else if (is_reg_name(dst) && (src.find('[') != std::string::npos || src.rfind("0x", 0) == 0)) {
                    if (dst != "rdi" || src.rfind("QWORD PTR [rip+", 0) != 0) reg.erase(dst);
                }

                if (dst == "rax" && src == "QWORD PTR [rax+0x10]") accessor_offset = 0x10;
                else if (dst == "rax" && src == "QWORD PTR [rax+0x18]") accessor_offset = 0x18;
            }
        } else if (x.mnemonic == "lea") {
            std::string dst, src;
            if (split_mov_operands(x.operands, dst, src) && is_reg_name(dst)) reg.erase(dst);
        }

        if ((x.mnemonic == "call" || x.mnemonic == "callq") && x.operands == "rax") {
            if (pending.valid && accessor_offset != 0 && i - pending.index <= 10) {
                VariableScope scope = VariableScope::Unknown;
                auto rit = reg.find("rdi");
                if (rit != reg.end()) scope = rit->second;
                out.push_back({pending.index, i, pending.name, pending.id_va, scope, accessor_offset == 0x18});
            }
            pending.valid = false;
            accessor_offset = 0;
            reg.erase("rax");
            reg.erase("rcx"); reg.erase("rdx"); reg.erase("rsi"); reg.erase("rdi");
            reg.erase("r8"); reg.erase("r9"); reg.erase("r10"); reg.erase("r11");
        } else if (x.mnemonic == "call" || x.mnemonic == "callq") {
            reg.erase("rax");
            reg.erase("rcx"); reg.erase("rdx"); reg.erase("rsi"); reg.erase("rdi");
            reg.erase("r8"); reg.erase("r9"); reg.erase("r10"); reg.erase("r11");
        }
    }
    return out;
}

std::vector<VariableCopyAssignment> recover_variable_copies(
    const std::vector<Instruction>& ins,
    const std::vector<AccessSite>& sites) {
    std::vector<VariableCopyAssignment> out;

    struct TempSource { uint64_t slot{}; uint64_t helper{}; const AccessSite* source{}; };
    std::vector<TempSource> temps;

    for (const auto& src : sites) {
        if (src.write) continue;
        std::optional<uint64_t> slot;
        uint64_t helper = 0;
        bool rsi_is_rax = false;
        for (size_t j = src.call_index + 1; j < ins.size() && j <= src.call_index + 8; ++j) {
            std::string dst, val;
            if ((ins[j].mnemonic == "lea" || ins[j].mnemonic == "mov") && split_mov_operands(ins[j].operands, dst, val)) {
                if (dst == "rdi") slot = rsp_slot(val);
                if (dst == "rsi" && val == "rax") rsi_is_rax = true;
            }
            if ((ins[j].mnemonic == "call" || ins[j].mnemonic == "callq") && ins[j].has_branch_target && slot && rsi_is_rax) {
                helper = ins[j].branch_target;
                temps.push_back({*slot, helper, &src});
                break;
            }
        }
    }

    for (const auto& dst : sites) {
        if (!dst.write) continue;
        std::set<std::string> target_aliases{"rax"};
        std::optional<uint64_t> source_slot;
        uint64_t helper = 0;
        uint64_t assign_va = ins[dst.call_index].address;
        for (size_t j = dst.call_index + 1; j < ins.size() && j <= dst.call_index + 14; ++j) {
            std::string a, b;
            if (ins[j].mnemonic == "mov" && split_mov_operands(ins[j].operands, a, b)) {
                if (is_reg_name(a) && target_aliases.contains(b)) target_aliases.insert(a);
                if (a == "rdi" && target_aliases.contains(b)) {

                }
                if (a == "rsi") source_slot = rsp_slot(b);
            } else if (ins[j].mnemonic == "lea" && split_mov_operands(ins[j].operands, a, b)) {
                if (a == "rsi") source_slot = rsp_slot(b);
            }
            if ((ins[j].mnemonic == "call" || ins[j].mnemonic == "callq") && ins[j].has_branch_target && source_slot) {
                helper = ins[j].branch_target;
                assign_va = ins[j].address;
                break;
            }
        }
        if (!source_slot || !helper) continue;
        const TempSource* best = nullptr;
        for (const auto& t : temps) {
            if (t.slot != *source_slot || t.helper != helper || t.source->call_index >= dst.call_index) continue;
            if (!best || t.source->call_index > best->source->call_index) best = &t;
        }
        if (best) out.push_back({assign_va, dst.variable, dst.scope, best->source->variable, best->source->scope});
    }

    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b){ return a.instruction_va < b.instruction_va; });
    out.erase(std::unique(out.begin(), out.end(), [](const auto& a, const auto& b){
        return a.instruction_va == b.instruction_va && a.target == b.target && a.source == b.source;
    }), out.end());
    return out;
}

std::string normalize_reg(std::string r);
bool parse_immediate(std::string s, uint64_t& out);

enum class HelperKind {
    Unknown,
    AddAssign, SubAssign, MulAssign, DivAssign, ModAssign,
    AddExprInt, SubExprInt, MulExprDouble, DivExprDouble, ModExprInt,
    CopyValue, GeInt, LeInt, GtInt, LtInt, EqInt
};

HelperKind classify_helper_impl(const std::filesystem::path& executable, uint64_t target, int depth, std::set<uint64_t>& visiting) {
    if (!target || depth > 3 || visiting.contains(target)) return HelperKind::Unknown;
    visiting.insert(target);
    auto body = disassemble_range(executable, target, target + 0x240);
    auto first_ret = std::find_if(body.begin(), body.end(), [](const Instruction& i){ return i.mnemonic == "ret" || i.mnemonic == "retq"; });
    if (first_ret != body.end()) body.erase(first_ret + 1, body.end());
    bool addsd = false, subsd = false, mulsd = false, divsd = false;
    bool setns_al = false, setle_bl = false, setne_bpl = false, setg_al = false, sets_bl = false, sete_al = false;
    bool compare_mode_one = false;
    bool idiv_seen = false;
    bool stores_remainder = false;
    bool stores_quotient = false;
    bool copy_load_xmm = false, copy_store_type = false, copy_store_flags = false, copy_store_payload = false;
    std::vector<uint64_t> calls;
    for (const auto& x : body) {
        if (x.mnemonic == "addsd") addsd = true;
        if (x.mnemonic == "subsd") subsd = true;
        if (x.mnemonic == "mulsd") mulsd = true;
        if (x.mnemonic == "divsd") divsd = true;
        if (x.mnemonic == "setns" && x.operands == "al") setns_al = true;
        if (x.mnemonic == "sete" && x.operands == "al") sete_al = true;
        if (x.mnemonic == "setg" && x.operands == "al") setg_al = true;
        if (x.mnemonic == "sets" && x.operands == "bl") sets_bl = true;
        if (x.mnemonic == "setle" && x.operands == "bl") setle_bl = true;
        if (x.mnemonic == "setne" && x.operands == "bpl") setne_bpl = true;
        if (x.mnemonic == "mov" && x.operands == "edx,0x1") compare_mode_one = true;
        if (x.mnemonic == "idiv") idiv_seen = true;
        if ((x.mnemonic == "movups" || x.mnemonic == "movupd" || x.mnemonic == "movaps" || x.mnemonic == "movapd") && x.operands.find("[rsi]") != std::string::npos) copy_load_xmm = true;
        if (x.mnemonic == "mov" && x.operands.rfind("DWORD PTR [rbx+0xc],",0)==0) copy_store_type = true;
        if (x.mnemonic == "mov" && x.operands.rfind("DWORD PTR [rbx+0x8],",0)==0) copy_store_flags = true;
        if (x.mnemonic == "mov" && x.operands.rfind("QWORD PTR [rbx],",0)==0) copy_store_payload = true;
        if (x.mnemonic == "mov" && x.operands.find("[rbx]") != std::string::npos) {
            if (x.operands.find(",edx") != std::string::npos || x.operands.find(",rdx") != std::string::npos) stores_remainder = true;
            if (x.operands.find(",eax") != std::string::npos || x.operands.find(",rax") != std::string::npos) stores_quotient = true;
        }
        if ((x.mnemonic == "call" || x.mnemonic == "callq") && x.has_branch_target) calls.push_back(x.branch_target);
    }
    visiting.erase(target);
    if (copy_load_xmm && copy_store_type && copy_store_flags && copy_store_payload) return HelperKind::CopyValue;
    if (sete_al && !setg_al && !setns_al) return HelperKind::EqInt;
    if (compare_mode_one && setns_al) return HelperKind::GeInt;
    if (compare_mode_one && setg_al) return HelperKind::GtInt;
    if (compare_mode_one && sets_bl && setne_bpl) return HelperKind::LtInt;
    if (compare_mode_one && setle_bl && setne_bpl) return HelperKind::LeInt;
    if (addsd && !subsd && !mulsd && !divsd) return HelperKind::AddAssign;
    if (subsd && !addsd && !mulsd && !divsd) return HelperKind::SubAssign;
    if (mulsd && !addsd && !subsd && !divsd) return HelperKind::MulAssign;
    if (divsd && !addsd && !subsd && !mulsd) return HelperKind::DivAssign;
    if (idiv_seen && stores_remainder && !stores_quotient) return HelperKind::ModAssign;
    if (idiv_seen && stores_quotient && !stores_remainder) return HelperKind::DivAssign;

    for (const auto callee : calls) {
        const uint64_t distance = callee > target ? callee - target : target - callee;
        if (distance > 0x10000) continue;
        std::set<uint64_t> child_visiting = visiting;
        const auto child = classify_helper_impl(executable, callee, depth + 1, child_visiting);
        if (child == HelperKind::AddAssign) return HelperKind::AddExprInt;
        if (child == HelperKind::SubAssign) return HelperKind::SubExprInt;
        if (child == HelperKind::MulAssign) return HelperKind::MulExprDouble;
        if (child == HelperKind::DivAssign) return HelperKind::DivExprDouble;
        if (child == HelperKind::ModAssign) return HelperKind::ModExprInt;
    }
    return HelperKind::Unknown;
}

HelperKind classify_helper(const std::filesystem::path& executable, uint64_t target) {
    std::set<uint64_t> visiting;
    return classify_helper_impl(executable, target, 0, visiting);
}

std::optional<std::pair<std::string,uint64_t>> memory_reg_offset(const std::string& op);

std::vector<CompoundAssignment> recover_compound_assignments(
    const std::vector<Instruction>& ins,
    const std::vector<AccessSite>& sites,
    const std::unordered_map<uint64_t, HelperKind>& helpers,
    const ElfImage& elf) {
    struct AccessReg { const AccessSite* site{}; size_t set_at{}; };
    std::unordered_map<std::string, AccessReg> reg_source, reg_target;
    std::vector<CompoundAssignment> out;
    std::set<const AccessSite*> direct_inc_sites;

    std::unordered_map<size_t, const AccessSite*> site_by_call;
    for (const auto& a : sites) site_by_call[a.call_index] = &a;

    const auto cfg = ins.empty() ? std::vector<BasicBlock>{} : build_cfg(ins, ins.front().address, ins.back().address + 16);
    const auto dom = compute_dominators(cfg);
    auto block_for = [&](uint64_t at) -> uint64_t {
        for (const auto& b : cfg) if (at >= b.start && at < b.end) return b.start;
        return 0;
    };
    struct WriteAlias { const AccessSite* site{}; std::string reg; uint64_t block{}; };
    std::vector<WriteAlias> write_aliases;
    for (const auto& a : sites) if (a.write) {
        for (size_t j=a.call_index+1; j<ins.size() && j<=a.call_index+4; ++j) {
            std::string d, src;
            if (ins[j].mnemonic=="mov" && split_mov_operands(ins[j].operands,d,src) && normalize_reg(src)=="rax" && is_reg_name(normalize_reg(d))) {
                write_aliases.push_back({&a,normalize_reg(d),block_for(ins[j].address)}); break;
            }
        }
    }

    for (size_t i = 0; i < ins.size(); ++i) {
        if (auto sit = site_by_call.find(i); sit != site_by_call.end()) {
            const auto* a = sit->second;
            for (size_t j = i + 1; j < ins.size() && j <= i + 4; ++j) {
                std::string dst, src;
                if (ins[j].mnemonic == "mov" && split_mov_operands(ins[j].operands, dst, src) && src == "rax" && is_reg_name(dst)) {
                    if (a->write) reg_target[normalize_reg(dst)] = {a, j};
                    else reg_source[normalize_reg(dst)] = {a, j};
                    break;
                }
            }
        }

        const auto& x = ins[i];

        if (x.mnemonic == "inc") {
            auto mem = memory_reg_offset(x.operands);
            if (mem && mem->second == 0) {
                const uint64_t ib = block_for(x.address);
                const WriteAlias* best = nullptr;
                for (const auto& wa : write_aliases) {
                    if (wa.reg != mem->first || wa.site->call_index >= i || !wa.block || !ib) continue;
                    auto bi=dom.index.find(ib);
                    if (bi==dom.index.end() || !bit_has(dom,bi->second,wa.block)) continue;
                    if (!best || wa.site->call_index > best->site->call_index) best=&wa;
                }
                if (best && direct_inc_sites.insert(best->site).second) {
                    CompoundAssignment c; c.instruction_va=x.address; c.target=best->site->variable; c.target_scope=best->site->scope;
                    c.op="+="; c.has_immediate=true; c.immediate=1.0; out.push_back(std::move(c));
                }
            }
        }

        if ((x.mnemonic != "call" && x.mnemonic != "callq") || !x.has_branch_target) continue;
        auto hk = helpers.find(x.branch_target);
        if (hk == helpers.end() || (hk->second != HelperKind::AddAssign && hk->second != HelperKind::SubAssign && hk->second != HelperKind::MulAssign && hk->second != HelperKind::DivAssign && hk->second != HelperKind::ModAssign)) continue;

        std::string dst_reg, src_reg;
        std::optional<double> immediate;
        for (size_t back = 0; back < 10 && i > back; ++back) {
            const auto& q = ins[i - 1 - back];
            std::string a,b;
            if (q.mnemonic == "mov" && split_mov_operands(q.operands,a,b)) {
                if (a == "rdi" && is_reg_name(b) && dst_reg.empty()) dst_reg = normalize_reg(b);
                if (a == "rsi" && is_reg_name(b) && src_reg.empty()) src_reg = normalize_reg(b);
            }
            if (!immediate && q.mnemonic == "movsd" && split_mov_operands(q.operands,a,b) && a == "xmm0" && q.has_referenced_va) {
                auto off=elf.va_to_offset(q.referenced_va);
                if(off && *off+8<=elf.bytes().size()) {
                    uint64_t bits=0; std::memcpy(&bits,elf.bytes().data()+*off,8);
                    const double v=std::bit_cast<double>(bits); if(std::isfinite(v)) immediate=v;
                }
            }
        }
        auto direct_di = reg_target.find("rdi");
        if (direct_di != reg_target.end() && i >= direct_di->second.set_at && i - direct_di->second.set_at <= 32) dst_reg = "rdi";
        if (dst_reg.empty()) continue;
        auto di = reg_target.find(dst_reg);
        if (di == reg_target.end() || i - di->second.set_at > 32) continue;
        auto si = reg_source.find(src_reg);
        if (!immediate && (src_reg.empty() || si == reg_source.end() || i - si->second.set_at > 32)) continue;
        CompoundAssignment c;
        c.instruction_va = x.address;
        c.target = di->second.site->variable; c.target_scope = di->second.site->scope;
        if(immediate){c.has_immediate=true;c.immediate=*immediate;}
        else { c.source = si->second.site->variable; c.source_scope = si->second.site->scope; }
        switch (hk->second) {
            case HelperKind::AddAssign: c.op = "+="; break;
            case HelperKind::SubAssign: c.op = "-="; break;
            case HelperKind::MulAssign: c.op = "*="; break;
            case HelperKind::DivAssign: c.op = "/="; break;
            case HelperKind::ModAssign: c.op = "%="; break;
            default: break;
        }
        out.push_back(std::move(c));
    }
    std::sort(out.begin(), out.end(), [](const auto& a,const auto& b){return a.instruction_va<b.instruction_va;});
    out.erase(std::unique(out.begin(),out.end(),[](const auto&a,const auto&b){return a.instruction_va==b.instruction_va;}),out.end());
    return out;
}

std::vector<RelationalBranch> recover_relational_branches(
    const std::vector<Instruction>& ins,
    const std::vector<AccessSite>& sites,
    const std::unordered_map<uint64_t, HelperKind>& helpers,
    uint64_t function_end) {
    std::unordered_map<size_t, const AccessSite*> read_by_call;
    for (const auto& a : sites) if (!a.write) read_by_call[a.call_index] = &a;
    std::vector<RelationalBranch> out;
    for (const auto& [call_index, site] : read_by_call) {
        std::set<std::string> result_aliases{"rax"};
        for (size_t j = call_index + 1; j < ins.size() && j <= call_index + 12; ++j) {
            const auto& x = ins[j];
            if ((x.mnemonic == "call" || x.mnemonic == "callq") && x.has_branch_target) {
                auto hit = helpers.find(x.branch_target);
                if (hit == helpers.end() || (hit->second != HelperKind::GeInt && hit->second != HelperKind::LeInt && hit->second != HelperKind::GtInt && hit->second != HelperKind::LtInt && hit->second != HelperKind::EqInt)) continue;
                bool rdi_ok = false;
                std::optional<long long> imm;
                for (size_t back=0; back<6 && j>back; ++back) {
                    std::string a,b;
                    const auto& q=ins[j-1-back];
                    if ((q.mnemonic=="mov"||q.mnemonic=="xor") && split_mov_operands(q.operands,a,b)) {
                        if (a=="rdi" && result_aliases.contains(normalize_reg(b))) rdi_ok=true;
                        if (a=="esi") { uint64_t v=0; if(parse_immediate(b,v)) imm=static_cast<int32_t>(v); }
                        if (q.mnemonic=="xor" && a=="esi" && b=="esi") imm=0;
                    }
                }
                if (!rdi_ok || !imm) continue;
                size_t t=j+1;
                while(t<ins.size() && t<=j+3 && !(ins[t].mnemonic=="test" && ins[t].operands=="al,al")) ++t;
                if(t>=ins.size()||t+1>=ins.size()) continue;
                const auto& br=ins[t+1];
                if((br.mnemonic!="je"&&br.mnemonic!="jne")||!br.has_branch_target) continue;
                const uint64_t fall=t+2<ins.size()?ins[t+2].address:function_end;
                RelationalBranch b;
                b.compare_call_va=x.address; b.branch_va=br.address; b.variable=site->variable; b.scope=site->scope;
                switch (hit->second) {
                    case HelperKind::GeInt: b.op=">="; break;
                    case HelperKind::LeInt: b.op="<="; break;
                    case HelperKind::GtInt: b.op=">"; break;
                    case HelperKind::LtInt: b.op="<"; break;
                    case HelperKind::EqInt: b.op="=="; break;
                    default: break;
                }
                b.value=static_cast<double>(*imm);
                if(br.mnemonic=="je"){b.true_target=fall;b.false_target=br.branch_target;}else{b.true_target=br.branch_target;b.false_target=fall;}
                out.push_back(std::move(b));
                break;
            }
            std::string a,b;
            if (x.mnemonic=="mov" && split_mov_operands(x.operands,a,b) && is_reg_name(a) && result_aliases.contains(normalize_reg(b)) && a!="rdi" && a!="rsi") result_aliases.insert(normalize_reg(a));
        }
    }
    std::sort(out.begin(),out.end(),[](const auto&a,const auto&b){return a.compare_call_va<b.compare_call_va;});
    out.erase(std::unique(out.begin(),out.end(),[](const auto&a,const auto&b){return a.compare_call_va==b.compare_call_va;}),out.end());
    return out;
}
std::vector<RecoveredSwitch> recover_switches(
    const std::vector<Instruction>& ins,
    const std::vector<EqualityBranch>& eqs) {
    struct Key {
        std::string var;
        VariableScope scope;
        uint64_t dispatch;
        bool operator<(const Key& o) const {
            if (var != o.var) return var < o.var;
            if (scope != o.scope) return static_cast<int>(scope) < static_cast<int>(o.scope);
            return dispatch < o.dispatch;
        }
    };
    std::map<Key, std::vector<const EqualityBranch*>> groups;
    for (const auto& e : eqs) groups[{e.variable,e.scope,e.true_target}].push_back(&e);
    std::vector<RecoveredSwitch> out;
    for (auto& [key, branches] : groups) {
        if (branches.size() < 2) continue;
        std::sort(branches.begin(),branches.end(),[](auto*a,auto*b){return a->compare_call_va<b->compare_call_va;});
        auto dit=std::lower_bound(ins.begin(),ins.end(),key.dispatch,[](const Instruction&a,uint64_t v){return a.address<v;});
        if(dit==ins.end()||dit->address!=key.dispatch) continue;
        const size_t base=static_cast<size_t>(dit-ins.begin());
        std::unordered_map<int,uint64_t> ordinal_target;
        uint64_t default_target=0;
        for(size_t j=base;j<ins.size()&&j<=base+18;++j){
            const auto& x=ins[j];
            if(x.mnemonic=="cmp"&&x.operands.rfind("eax,0x",0)==0&&j+1<ins.size()&&ins[j+1].mnemonic=="je"&&ins[j+1].has_branch_target){
                ordinal_target[static_cast<int>(parse_hex(x.operands.substr(6)))]=ins[j+1].branch_target;
            }
            if(x.mnemonic=="test"&&x.operands=="eax,eax"&&j+1<ins.size()&&ins[j+1].has_branch_target){
                const auto& br=ins[j+1];
                const uint64_t fall=j+2<ins.size()?ins[j+2].address:0;
                if(br.mnemonic=="jne"){ordinal_target[0]=fall;default_target=br.branch_target;}
                else if(br.mnemonic=="je"){ordinal_target[0]=br.branch_target;default_target=fall;}
            }
        }
        if(ordinal_target.empty()) continue;
        RecoveredSwitch sw; sw.variable=key.var; sw.scope=key.scope; sw.dispatch_va=key.dispatch; sw.default_target=default_target;
        for(size_t i=0;i<branches.size();++i){
            auto it=ordinal_target.find(static_cast<int>(i));
            if(it!=ordinal_target.end()) sw.cases.push_back({branches[i]->value,it->second});
        }
        if(sw.cases.size()>=2) out.push_back(std::move(sw));
    }
    return out;
}

std::vector<TruthyBranch> recover_truthy_branches(
    const std::vector<Instruction>& ins,
    const std::unordered_map<uint64_t, std::string>& variables,
    uint64_t function_end) {
    std::vector<TruthyBranch> out;
    for (size_t i = 0; i < ins.size(); ++i) {
        const auto& x = ins[i];
        if (x.mnemonic != "mov" || x.operands.rfind("esi,DWORD PTR [rip+", 0) != 0 || !x.has_referenced_va) continue;
        auto vit = variables.find(x.referenced_va);
        if (vit == variables.end()) continue;

        bool read_seen = false;
        bool truthy_call_seen = false;
        for (size_t j = i + 1; j < ins.size() && j <= i + 12; ++j) {
            const auto& y = ins[j];
            if ((y.mnemonic == "call" || y.mnemonic == "callq") && y.operands == "rax") {
                read_seen = true;
                continue;
            }
            if (!read_seen) continue;

            if ((y.mnemonic == "call" || y.mnemonic == "callq") && y.has_branch_target) {
                truthy_call_seen = true;
                continue;
            }
            if (!truthy_call_seen || y.mnemonic != "test" || y.operands != "al,al") continue;
            if (j + 1 >= ins.size()) break;
            const auto& br = ins[j + 1];
            if ((br.mnemonic != "je" && br.mnemonic != "jne") || !br.has_branch_target) break;
            const uint64_t fallthrough = j + 2 < ins.size() ? ins[j + 2].address : function_end;
            TruthyBranch b;
            b.variable_read_va = x.address;
            b.branch_va = br.address;
            b.variable = vit->second;
            if (br.mnemonic == "je") {
                b.true_target = fallthrough;
                b.false_target = br.branch_target;
            } else {
                b.true_target = br.branch_target;
                b.false_target = fallthrough;
            }
            out.push_back(std::move(b));
            break;
        }
    }
    return out;
}

struct ExprState {
    std::string expression;
    std::string kind;
    VariableScope scope{VariableScope::Unknown};
    uint32_t raw_type{0xffffffffu};
    uint64_t raw_payload{};
    std::string callee;
    std::vector<RecoveredArgument> children;
};

RecoveredArgument recovered_argument_from_expr(const ExprState& e, uint64_t slot=0) {
    RecoveredArgument a;
    a.expression=e.expression; a.kind=e.kind; a.scope=e.scope; a.value_slot=slot;
    a.raw_type=e.raw_type; a.raw_payload=e.raw_payload; a.callee=e.callee; a.children=e.children;
    return a;
}

std::string normalize_reg(std::string r) {
    static const std::unordered_map<std::string, std::string> aliases = {
        {"eax","rax"},{"ax","rax"},{"al","rax"},
        {"ebx","rbx"},{"bx","rbx"},{"bl","rbx"},
        {"ecx","rcx"},{"cx","rcx"},{"cl","rcx"},
        {"edx","rdx"},{"dx","rdx"},{"dl","rdx"},
        {"esi","rsi"},{"si","rsi"},{"sil","rsi"},
        {"edi","rdi"},{"di","rdi"},{"dil","rdi"},
        {"ebp","rbp"},{"bp","rbp"},{"bpl","rbp"},
        {"esp","rsp"},{"sp","rsp"},{"spl","rsp"},
        {"r8d","r8"},{"r9d","r9"},{"r10d","r10"},{"r11d","r11"},
        {"r12d","r12"},{"r13d","r13"},{"r14d","r14"},{"r15d","r15"}
    };
    auto it = aliases.find(r);
    return it == aliases.end() ? r : it->second;
}

std::optional<uint64_t> rsp_mem_offset(const std::string& op) {
    static const std::regex re(R"(^(?:(?:BYTE|WORD|DWORD|QWORD|XMMWORD) PTR )?\[rsp(?:\+0x([0-9a-fA-F]+))?\]$)");
    std::smatch m;
    if (!std::regex_match(op, m, re)) return std::nullopt;
    return m[1].matched ? std::optional<uint64_t>(parse_hex(m[1].str())) : std::optional<uint64_t>(0);
}

std::optional<std::string> memory_base_reg(const std::string& op) {
    static const std::regex re(R"(^(?:(?:BYTE|WORD|DWORD|QWORD|XMMWORD) PTR )?\[([a-z0-9]+)(?:[+\-].*)?\]$)");
    std::smatch m;
    if (!std::regex_match(op, m, re)) return std::nullopt;
    return normalize_reg(m[1].str());
}

std::optional<std::pair<std::string,uint64_t>> memory_reg_offset(const std::string& op) {
    static const std::regex re(R"(^(?:(?:BYTE|WORD|DWORD|QWORD|XMMWORD) PTR )?\[([a-z0-9]+)(?:\+0x([0-9a-fA-F]+))?\]$)");
    std::smatch m;
    if (!std::regex_match(op,m,re)) return std::nullopt;
    return std::make_pair(normalize_reg(m[1].str()), m[2].matched ? parse_hex(m[2].str()) : uint64_t(0));
}

bool parse_immediate(std::string s, uint64_t& out) {
    const auto hash = s.find('#');
    if (hash != std::string::npos) s.resize(hash);
    s = trim(s);
    if (s.empty()) return false;
    if (s[0] == '-') {
        char* end = nullptr;
        const long long v = std::strtoll(s.c_str(), &end, 0);
        if (!end || *end) return false;
        out = static_cast<uint64_t>(v);
        return true;
    }
    if (s.rfind("0x", 0) == 0 || std::isdigit(static_cast<unsigned char>(s[0]))) {
        char* end = nullptr;
        const unsigned long long v = std::strtoull(s.c_str(), &end, 0);
        if (!end || *end) return false;
        out = static_cast<uint64_t>(v);
        return true;
    }
    return false;
}

std::string scoped_text(VariableScope scope, const std::string& name) {
    if (scope == VariableScope::Self) return "self." + name;
    if (scope == VariableScope::Other) return "other." + name;
    if (scope == VariableScope::Global) return "global." + name;
    return "unknown." + name;
}

std::string quote_expr_string(const std::string& in) {
    std::string o = "\"";
    for (unsigned char c : in) {
        if (c == '\\' || c == '"') { o += '\\'; o += char(c); }
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else if (c >= 0x20 && c < 0x7f) o += char(c);
        else { char b[5]; std::snprintf(b,sizeof(b),"\\x%02x",c); o += b; }
    }
    o += "\"";
    return o;
}

ExprState decode_raw_value(uint32_t type, uint64_t payload, const IffInfo& iff) {
    ExprState e; e.raw_type=type; e.raw_payload=payload;
    if (type == 0xffffffu || type == 0xffffffffu) { e.kind="unknown"; return e; }
    if (type == 0) {
        const double v=std::bit_cast<double>(payload);
        if(std::isfinite(v)){std::ostringstream ss;ss<<std::setprecision(17)<<v;e.expression=ss.str();e.kind="number";}
        return e;
    }
    if (type == 0x0d) { const double v=std::bit_cast<double>(payload);e.expression=v!=0.0?"true":"false";e.kind="boolean";return e; }
    if (type == 5 && payload == 0) { e.expression="undefined";e.kind="undefined";return e; }
    if (type == 0x0f) {
        const uint32_t ref_index=static_cast<uint32_t>(payload);
        const uint32_t ref_class=static_cast<uint32_t>((payload>>32)&0x00ffffffu);
        static const std::unordered_map<uint32_t,std::pair<const char*,const char*>> ref_tables = {
            {0,{"OBJT","resource_object"}}, {1,{"SPRT","resource_sprite"}},
            {2,{"SOND","resource_sound"}}, {3,{"ROOM","resource_room"}}
        };
        auto rt=ref_tables.find(ref_class);
        if(rt!=ref_tables.end()){auto name=iff.resource_name(rt->second.first,ref_index);if(!name.empty()){e.expression=name;e.kind=rt->second.second;return e;}}
        std::ostringstream ss;ss<<"ref(class="<<ref_class<<",index="<<ref_index<<")";e.expression=ss.str();e.kind="reference";return e;
    }
    std::ostringstream ss;ss<<"yyc_value(type="<<type<<",payload=0x"<<std::hex<<payload<<")";e.expression=ss.str();e.kind="raw";return e;
}

std::unordered_map<uint64_t, ExprState> discover_static_values(const ElfImage& elf, const IffInfo& iff) {
    struct Candidate { uint64_t slot{}, helper{}; std::string text; };
    std::vector<Candidate> candidates;
    std::map<uint64_t,size_t> helper_counts;
    const auto& d=elf.bytes();
    for(const auto& sec:elf.sections()){
        if(!sec.executable()||sec.offset+sec.size>d.size())continue;
        for(uint64_t o=sec.offset;o+15<=sec.offset+sec.size;++o){
            if(d[o]!=0xbf||d[o+5]!=0xbe||d[o+10]!=0xe8)continue;
            const uint64_t slot=read_u32(d,o+1), strva=read_u32(d,o+6);
            if(!elf.is_writable_va(slot))continue;
            auto text=elf.cstring_at_va(strva,4096);
            if(!text)continue;
            auto callva=elf.offset_to_va(o+10); if(!callva)continue;
            const uint64_t helper=uint64_t(int64_t(*callva+5)+read_i32(d,o+11));
            if(!elf.is_executable_va(helper))continue;
            candidates.push_back({slot,helper,*text});++helper_counts[helper];
        }
    }
    std::unordered_map<uint64_t,std::set<uint64_t>> helper_slots;
    for(const auto& c:candidates) helper_slots[c.helper].insert(c.slot);
    uint64_t best=0;size_t distinct=0,total=0;
    for(const auto& [h,slots]:helper_slots){const size_t n=slots.size();const size_t t=helper_counts[h];if(n>distinct||(n==distinct&&t>total)){best=h;distinct=n;total=t;}}
    std::unordered_map<uint64_t,ExprState> out;
    if(distinct<4)return out;
    for(const auto& c:candidates)if(c.helper==best){ExprState e;e.expression=quote_expr_string(c.text);e.kind="string";e.raw_type=1;out[c.slot]=std::move(e);}

    for(const auto& sec:elf.sections()){
        if(!sec.writable()||sec.type==8||sec.offset+sec.size>d.size())continue;
        for(uint64_t o=(sec.offset+7)&~uint64_t(7);o+16<=sec.offset+sec.size;o+=8){
            const uint32_t type=read_u32(d,o+12);
            if(type!=0&&type!=5&&type!=0x0d&&type!=0x0f)continue;
            uint64_t payload=0;std::memcpy(&payload,d.data()+o,8);
            auto va=elf.offset_to_va(o);if(!va)continue;
            auto e=decode_raw_value(type,payload,iff);if(!e.expression.empty())out[*va]=std::move(e);
        }
    }
    return out;
}

ExprState raw_stack_expr(
    uint64_t slot,
    const std::unordered_map<uint64_t, uint64_t>& qwords,
    const std::unordered_map<uint64_t, uint32_t>& dwords,
    const IffInfo& iff) {
    auto tit=dwords.find(slot+12);
    if(tit==dwords.end()) return {};
    auto pit=qwords.find(slot);
    const uint64_t payload=pit==qwords.end()?0:pit->second;
    return decode_raw_value(tit->second,payload,iff);
}

void recover_call_arguments_and_equalities(
    const std::vector<Instruction>& ins,
    const std::vector<AccessSite>& sites,
    std::vector<NamedCall>& named_calls,
    std::vector<BuiltinCall>& builtin_calls,
    std::vector<EqualityBranch>& equality_branches,
    std::vector<ExpressionBranch>& expression_branches,
    std::vector<LocalValueAssignment>& local_assignments,
    std::vector<ReturnValueWrite>& return_values,
    std::vector<VariableValueAssignment>& variable_value_assignments,
    std::vector<DynamicInstanceAssignment>& dynamic_instance_assignments,
    std::vector<DynamicValueCall>& dynamic_value_calls,
    std::vector<TargetUserEventCall>& target_user_events,
    const std::unordered_map<uint64_t, std::string>& variable_by_id,
    const IffInfo& iff,
    const std::unordered_map<uint64_t, ExprState>& static_values,
    const std::unordered_map<uint64_t, std::string>& gml_by_va,
    const std::unordered_map<uint64_t, HelperKind>& helpers,
    const std::unordered_map<uint64_t, std::string>& native_fast_calls,
    const ElfImage& elf) {
    std::unordered_map<size_t, ExprState> accessor_result;
    std::unordered_map<size_t, const AccessSite*> accessor_write;
    for (const auto& a : sites) {
        if (!a.write) accessor_result[a.call_index] = {scoped_text(a.scope, a.variable), "variable", a.scope, 0xffffffffu, 0};
        else accessor_write[a.call_index] = &a;
    }
    std::unordered_map<size_t, ExprState> fast_stack_expr_at;
    for (size_t i = 0; i < ins.size(); ++i) {
        const auto& call = ins[i];
        if ((call.mnemonic != "call" && call.mnemonic != "callq") || !call.has_branch_target) continue;
        auto fit = native_fast_calls.find(call.branch_target);
        if (fit == native_fast_calls.end()) continue;
        uint64_t imm_arg = 0; bool got_arg = false;
        for (size_t back = 0; back < 5 && i > back; ++back) {
            std::string d, src;
            const auto& q = ins[i - 1 - back];
            if (q.mnemonic == "mov" && split_mov_operands(q.operands, d, src) && normalize_reg(d) == "rdi" && parse_immediate(src, imm_arg)) { got_arg = true; break; }
        }
        if (!got_arg) continue;
        std::optional<uint64_t> payload_slot;
        for (size_t j = i + 1; j < ins.size() && j <= i + 28; ++j) {
            if (ins[j].mnemonic == "mov") {
                std::string d, src;
                if (split_mov_operands(ins[j].operands, d, src)) {
                    auto off = rsp_mem_offset(d); uint64_t v = 0;
                    if (off && d.rfind("DWORD PTR",0)==0 && parse_immediate(src,v) && static_cast<uint32_t>(v)==0xd && *off>=12) payload_slot=*off-12;
                }
            }
            if (payload_slot && ins[j].mnemonic == "movsd") {
                std::string d, src;
                if (split_mov_operands(ins[j].operands,d,src)) {
                    auto off=rsp_mem_offset(d);
                    if (off && *off==*payload_slot && src.rfind("xmm",0)==0) {
                        ExprState e; e.kind="builtin_call"; e.callee=fit->second;
                        RecoveredArgument a; a.kind="number"; a.expression=std::to_string(static_cast<int64_t>(imm_arg)); a.raw_type=7; a.raw_payload=imm_arg;
                        e.children={a}; e.expression=fit->second+"("+a.expression+")";
                        fast_stack_expr_at[j]=std::move(e); break;
                    }
                }
            }
        }
    }

    std::unordered_map<uint64_t, NamedCall*> named_at;
    for (auto& c : named_calls) named_at[c.instruction_va] = &c;
    std::unordered_map<uint64_t, BuiltinCall*> builtin_at;
    for (auto& c : builtin_calls) builtin_at[c.instruction_va] = &c;

    std::unordered_map<std::string, uint64_t> reg_addr;
    std::unordered_map<std::string, uint64_t> reg_imm;
    std::unordered_map<std::string, ExprState> reg_expr;
    std::unordered_map<std::string, std::string> reg_variable_id;
    std::unordered_map<std::string, const AccessSite*> reg_write_target;
    struct RawTargetValue { std::optional<uint64_t> payload; std::optional<uint32_t> type; };
    std::unordered_map<const AccessSite*, RawTargetValue> raw_target_values;
    std::unordered_map<uint64_t, uint64_t> pointer_slots;
    std::unordered_map<uint64_t, uint64_t> stack_qwords;
    std::unordered_map<uint64_t, uint32_t> stack_dwords;
    std::unordered_map<uint64_t, uint64_t> absolute_qwords;
    std::unordered_map<uint64_t, uint32_t> absolute_dwords;
    std::unordered_map<uint64_t, ExprState> stack_expr;
    std::unordered_map<std::string, ExprState> xmm_expr;
    std::set<std::string> argv_regs{"r8"};
    std::set<std::string> return_regs{"rdx"};
    std::set<std::string> self_regs{"rdi"};
    std::set<uint64_t> self_rvalue_slots;
    std::set<uint64_t> return_ptr_stack_slots;
    std::set<uint64_t> normalized_argv_ptr_slots;
    std::set<uint64_t> rvalue_stack_slots;
    std::optional<uint64_t> return_payload;
    std::optional<uint32_t> return_type;
    std::optional<ExprState> with_target_expr;

    auto clear_reg = [&](const std::string& r) {
        const auto n = normalize_reg(r);
        reg_addr.erase(n); reg_imm.erase(n); reg_expr.erase(n); reg_variable_id.erase(n); reg_write_target.erase(n); argv_regs.erase(n); return_regs.erase(n); self_regs.erase(n);
    };
    auto classify_slot = [&](uint64_t slot) {
        auto eit = stack_expr.find(slot);
        if (eit != stack_expr.end()) return eit->second;
        return raw_stack_expr(slot, stack_qwords, stack_dwords, iff);
    };
    auto classify_absolute = [&](uint64_t va) {
        auto sit=static_values.find(va); if(sit!=static_values.end()) return sit->second;
        auto tit=absolute_dwords.find(va+12); if(tit==absolute_dwords.end()) return ExprState{};
        const uint64_t payload=absolute_qwords.contains(va)?absolute_qwords[va]:0;
        return decode_raw_value(tit->second,payload,iff);
    };

    auto expr_ready = [](const ExprState& e) {
        return !e.expression.empty() && e.kind != "unknown" && e.kind != "raw";
    };
    auto local_name = [](uint64_t slot) { std::ostringstream ss; ss << "local_0x" << std::hex << slot; return ss.str(); };
    auto record_local = [&](uint64_t at, uint64_t slot, const ExprState& e) {
        if (!rvalue_stack_slots.contains(slot) || !expr_ready(e)) return;
        if (!local_assignments.empty() && local_assignments.back().instruction_va==at && local_assignments.back().stack_slot==slot) return;
        local_assignments.push_back({at,slot,local_name(slot),recovered_argument_from_expr(e,slot),0});
    };
    auto record_return = [&](uint64_t at, const ExprState& e) {
        if (!expr_ready(e)) return;
        if (e.kind=="undefined") return;
        if (!return_values.empty() && return_values.back().instruction_va==at && return_values.back().value.expression==e.expression) return;
        return_values.push_back({at,recovered_argument_from_expr(e),0});
    };
    auto record_variable_value = [&](uint64_t at, const AccessSite* target, const ExprState& e) {
        if (!target || target->scope == VariableScope::Unknown || !expr_ready(e)) return;
        if (!variable_value_assignments.empty()) {
            const auto& prev = variable_value_assignments.back();
            if (prev.instruction_va == at && prev.target == target->variable && prev.value.expression == e.expression) return;
        }
        VariableValueAssignment a;
        a.instruction_va = at; a.target = target->variable; a.target_scope = target->scope;
        a.value = recovered_argument_from_expr(e);
        variable_value_assignments.push_back(std::move(a));
    };
    auto make_binary = [&](const std::string& op, const ExprState& lhs, const ExprState& rhs) {
        ExprState e;
        if (!expr_ready(lhs) || !expr_ready(rhs)) return e;
        e.kind = "binary_op"; e.callee = op;
        e.children = {recovered_argument_from_expr(lhs), recovered_argument_from_expr(rhs)};
        e.expression = "(" + lhs.expression + " " + op + " " + rhs.expression + ")";
        return e;
    };
    auto make_unary = [&](const std::string& op, const ExprState& value) {
        ExprState e;
        if (!expr_ready(value)) return e;
        e.kind = "unary_op"; e.callee = op;
        e.children = {recovered_argument_from_expr(value)};
        e.expression = "(" + op + value.expression + ")";
        return e;
    };
    auto referenced_double = [&](uint64_t va) -> ExprState {
        auto off = elf.va_to_offset(va); if (!off || *off + 8 > elf.bytes().size()) return {};
        uint64_t bits = 0; std::memcpy(&bits, elf.bytes().data() + *off, 8);
        const double value = std::bit_cast<double>(bits);
        if (!std::isfinite(value)) return {};
        ExprState e; e.kind = "number"; e.raw_type = 0; e.raw_payload = bits;
        std::ostringstream ss; ss << std::setprecision(17) << value; e.expression = ss.str();
        return e;
    };
    auto source_expr = [&](const std::string& reg) {
        const auto n = normalize_reg(reg);
        if (reg_addr.contains(n)) return classify_slot(reg_addr[n]);
        if (reg_imm.contains(n)) return classify_absolute(reg_imm[n]);
        if (reg_expr.contains(n)) return reg_expr[n];
        return ExprState{};
    };

    for (size_t i = 0; i < ins.size(); ++i) {
        const auto& x = ins[i];
        if (x.mnemonic == "movsd" || x.mnemonic == "movlpd") {
            std::string dst, src;
            if (split_mov_operands(x.operands, dst, src)) {
                if (dst.rfind("xmm",0)==0 && x.has_referenced_va) {
                    auto e = referenced_double(x.referenced_va);
                    if (expr_ready(e)) xmm_expr[dst] = e; else xmm_expr.erase(dst);
                } else if (dst.rfind("xmm",0)==0) {
                    auto off = rsp_mem_offset(src);
                    if (off && stack_expr.contains(*off)) xmm_expr[dst] = stack_expr[*off];
                    else if (auto mem = memory_reg_offset(src); mem && mem->second == 0 && reg_expr.contains(mem->first)) xmm_expr[dst] = reg_expr[mem->first];
                    else if (src.rfind("xmm",0)==0 && xmm_expr.contains(src)) xmm_expr[dst] = xmm_expr[src];
                    else xmm_expr.erase(dst);
                } else if (auto off=rsp_mem_offset(dst); off && src.rfind("xmm",0)==0) {
                    auto fit = fast_stack_expr_at.find(i);
                    if (fit != fast_stack_expr_at.end()) { stack_expr[*off] = fit->second; record_local(x.address,*off,fit->second); }
                    else if (xmm_expr.contains(src)) stack_expr[*off] = xmm_expr[src];
                }
            }
        }
        if (x.mnemonic == "xorpd") {
            std::string dst, src;
            if (split_mov_operands(x.operands, dst, src) && dst.rfind("xmm", 0) == 0 && x.has_referenced_va) {
                auto off = elf.va_to_offset(x.referenced_va);
                bool sign_mask = false;
                if (off && *off + 8 <= elf.bytes().size()) {
                    uint64_t bits = 0;
                    std::memcpy(&bits, elf.bytes().data() + *off, 8);
                    sign_mask = bits == 0x8000000000000000ULL;
                }
                if (sign_mask) {
                    auto it = xmm_expr.find(dst);
                    if (it != xmm_expr.end() && expr_ready(it->second)) xmm_expr[dst] = make_unary("-", it->second);
                } else {
                    xmm_expr.erase(dst);
                }
            }
        }
        if ((x.mnemonic=="movups"||x.mnemonic=="movupd"||x.mnemonic=="movaps"||x.mnemonic=="movapd")) {
            std::string dst,src;
            if(split_mov_operands(x.operands,dst,src)){
                if(dst.rfind("xmm",0)==0 && x.has_referenced_va){auto it=static_values.find(x.referenced_va);if(it!=static_values.end())xmm_expr[dst]=it->second;else xmm_expr.erase(dst);}
                else if(dst.rfind("xmm",0)==0){auto base=memory_base_reg(src);if(base&&reg_expr.contains(*base))xmm_expr[dst]=reg_expr[*base];else xmm_expr.erase(dst);}
                else if(auto off=rsp_mem_offset(dst);off && src.rfind("xmm",0)==0){auto it=xmm_expr.find(src);if(it!=xmm_expr.end()){stack_expr[*off]=it->second;record_local(x.address,*off,it->second);}}
                else if(auto mem=memory_reg_offset(dst);mem && return_regs.contains(mem->first) && src.rfind("xmm",0)==0){auto it=xmm_expr.find(src);if(it!=xmm_expr.end())record_return(x.address,it->second);}
            }
        }
        if (x.mnemonic == "movabs" || x.mnemonic == "mov") {
            std::string dst, src;
            if (split_mov_operands(x.operands, dst, src)) {
                const auto ndst = normalize_reg(dst);
                const auto nsrc = normalize_reg(src);
                uint64_t imm = 0;
                if (is_reg_name(ndst) && parse_immediate(src, imm)) {
                    clear_reg(ndst); reg_imm[ndst] = imm;
                } else if (is_reg_name(ndst) && is_reg_name(nsrc)) {
                    const bool src_argv = argv_regs.contains(nsrc);
                    const bool src_return = return_regs.contains(nsrc);
                    const bool src_self = self_regs.contains(nsrc);
                    const auto src_write = reg_write_target.contains(nsrc) ? reg_write_target[nsrc] : nullptr;
                    clear_reg(ndst);
                    if (reg_addr.contains(nsrc)) reg_addr[ndst] = reg_addr[nsrc];
                    if (reg_imm.contains(nsrc)) reg_imm[ndst] = reg_imm[nsrc];
                    if (reg_expr.contains(nsrc)) reg_expr[ndst] = reg_expr[nsrc];
                    if (src_argv) argv_regs.insert(ndst);
                    if (src_return) return_regs.insert(ndst);
                    if (src_self) self_regs.insert(ndst);
                    if (src_write) reg_write_target[ndst] = src_write;
                } else if (is_reg_name(ndst)) {
                    ExprState inherited;
                    auto src_rsp = rsp_mem_offset(src);
                    const bool src_return_stack = src_rsp && return_ptr_stack_slots.contains(*src_rsp);
                    if(auto mem=memory_reg_offset(src);mem && argv_regs.contains(mem->first) && mem->second%8==0) {
                        const uint64_t index=mem->second/8; inherited.kind="argument"; inherited.expression="argument"+std::to_string(index); inherited.raw_payload=index;
                    } else if(src_rsp && stack_expr.contains(*src_rsp)) inherited=stack_expr[*src_rsp];
                    else { auto base = memory_base_reg(src); if (base && reg_expr.contains(*base)) inherited = reg_expr[*base]; }
                    clear_reg(ndst);
                    if (!inherited.expression.empty()) reg_expr[ndst] = inherited;
                    if (src_return_stack) return_regs.insert(ndst);
                    if (src_rsp && normalized_argv_ptr_slots.contains(*src_rsp)) argv_regs.insert(ndst);
                }

                if (x.has_referenced_va && is_reg_name(ndst)) {
                    auto vit=variable_by_id.find(x.referenced_va);
                    if(vit!=variable_by_id.end()) reg_variable_id[ndst]=vit->second;
                }

                auto off = rsp_mem_offset(dst);
                if (off) {
                    if (dst.rfind("DWORD PTR", 0) == 0 && parse_immediate(src, imm)) {
                        stack_dwords[*off] = static_cast<uint32_t>(imm);
                        if (*off >= 12) { rvalue_stack_slots.insert(*off-12); auto e=classify_slot(*off-12); if (static_cast<uint32_t>(imm)!=0xffffffu) record_local(x.address,*off-12,e); }
                    }
                    if (dst.rfind("QWORD PTR", 0) == 0) {
                        if (parse_immediate(src, imm)) stack_qwords[*off] = imm;
                        else if (reg_imm.contains(nsrc)) stack_qwords[*off] = reg_imm[nsrc];
                        if (reg_addr.contains(nsrc)) pointer_slots[*off] = reg_addr[nsrc];
                        else pointer_slots.erase(*off);
                        if (self_regs.contains(nsrc)) self_rvalue_slots.insert(*off);
                        if (reg_expr.contains(nsrc)) { stack_expr[*off] = reg_expr[nsrc]; record_local(x.address,*off,reg_expr[nsrc]); }
                        if (return_regs.contains(nsrc)) return_ptr_stack_slots.insert(*off); else return_ptr_stack_slots.erase(*off);
                    }
                }
                if (auto mem=memory_reg_offset(dst); mem && reg_write_target.contains(mem->first)) {
                    const auto* target = reg_write_target[mem->first];
                    auto& raw = raw_target_values[target];
                    if (mem->second == 0) {
                        if (reg_expr.contains(nsrc) && expr_ready(reg_expr[nsrc])) {
                            record_variable_value(x.address, target, reg_expr[nsrc]);
                        }
                        if (parse_immediate(src, imm)) raw.payload = imm;
                        else if (reg_imm.contains(nsrc)) raw.payload = reg_imm[nsrc];
                    } else if (mem->second == 12) {
                        if (parse_immediate(src, imm)) raw.type = static_cast<uint32_t>(imm);
                        else if (reg_imm.contains(nsrc)) raw.type = static_cast<uint32_t>(reg_imm[nsrc]);
                    }
                    if (raw.payload && raw.type) {
                        auto e = decode_raw_value(*raw.type, *raw.payload, iff);
                        record_variable_value(x.address, target, e);
                    }
                }
                if (auto mem=memory_reg_offset(dst); mem && return_regs.contains(mem->first)) {
                    if (mem->second==0) {
                        if (parse_immediate(src,imm)) return_payload=imm;
                        else if (reg_imm.contains(nsrc)) return_payload=reg_imm[nsrc];
                    } else if (mem->second==12 && parse_immediate(src,imm)) return_type=static_cast<uint32_t>(imm);
                    if (return_payload && return_type) record_return(x.address, decode_raw_value(*return_type,*return_payload,iff));
                }
                if (x.has_referenced_va && dst.find("[rip+") != std::string::npos) {
                    if (dst.rfind("DWORD PTR", 0) == 0 && parse_immediate(src, imm)) absolute_dwords[x.referenced_va] = static_cast<uint32_t>(imm);
                    if (dst.rfind("QWORD PTR", 0) == 0) {
                        if (parse_immediate(src, imm)) absolute_qwords[x.referenced_va] = imm;
                        else if (reg_imm.contains(nsrc)) absolute_qwords[x.referenced_va] = reg_imm[nsrc];
                    }
                }
            }
        } else if (x.mnemonic == "lea") {
            std::string dst, src;
            if (split_mov_operands(x.operands, dst, src)) {
                const auto ndst = normalize_reg(dst);
                if (is_reg_name(ndst)) {
                    auto mem = memory_reg_offset(src);
                    std::optional<uint64_t> derived_imm;
                    if (mem) {
                        auto it = reg_imm.find(mem->first);
                        if (it != reg_imm.end()) derived_imm = it->second + mem->second;
                    }
                    clear_reg(ndst);
                    if (auto off = rsp_mem_offset(src)) reg_addr[ndst] = *off;
                    if (derived_imm) reg_imm[ndst] = *derived_imm;
                }
            }
        } else if (x.mnemonic == "xor") {
            std::string dst, src;
            if (split_mov_operands(x.operands, dst, src) && normalize_reg(dst) == normalize_reg(src) && is_reg_name(normalize_reg(dst))) {
                const auto r = normalize_reg(dst); clear_reg(r); reg_imm[r] = 0;
            }
        }

        if (x.mnemonic == "neg" || x.mnemonic == "not") {
            const auto r = normalize_reg(trim(x.operands));
            if (reg_expr.contains(r)) {
                auto e = make_unary(x.mnemonic == "neg" ? "-" : "~", reg_expr[r]);
                if (expr_ready(e)) reg_expr[r] = std::move(e);
            }
        } else if (x.mnemonic == "add" || x.mnemonic == "sub" || x.mnemonic == "imul" || x.mnemonic == "and" || x.mnemonic == "or" || x.mnemonic == "xor" || x.mnemonic == "shl" || x.mnemonic == "shr" || x.mnemonic == "sar") {
            std::string dst, src;
            if (split_mov_operands(x.operands, dst, src)) {
                const auto d = normalize_reg(dst), r = normalize_reg(src);
                uint64_t immediate = 0;
                if ((x.mnemonic == "add" || x.mnemonic == "sub") && is_reg_name(d) && reg_imm.contains(d) && parse_immediate(src, immediate)) {
                    if (x.mnemonic == "add") reg_imm[d] += immediate;
                    else reg_imm[d] -= immediate;
                }
                if (reg_expr.contains(d)) {
                    ExprState rhs;
                    if (reg_expr.contains(r)) rhs = reg_expr[r];
                    else {
                        uint64_t imm = 0;
                        if (parse_immediate(src, imm)) {
                            rhs.kind = "number"; rhs.raw_type = 7; rhs.raw_payload = imm;
                            rhs.expression = std::to_string(static_cast<int64_t>(imm));
                        }
                    }
                    if (expr_ready(rhs)) {
                        std::string op = x.mnemonic;
                        if (op == "imul") op = "*";
                        else if (op == "and") op = "&";
                        else if (op == "or") op = "|";
                        else if (op == "xor") op = "^";
                        else if (op == "shl") op = "<<";
                        else if (op == "shr" || op == "sar") op = ">>";

                        ExprState e;
                        if (x.mnemonic == "xor" && rhs.kind == "number" && rhs.expression == "1" && reg_expr[d].kind == "boolean") e = make_unary("!", reg_expr[d]);
                        else e = make_binary(op, reg_expr[d], rhs);
                        if (expr_ready(e)) reg_expr[d] = std::move(e);
                    }
                }
            }
        }

        if ((x.mnemonic == "call" || x.mnemonic == "callq") && x.operands == "rax") {
            auto ait = accessor_result.find(i);
            auto wit = accessor_write.find(i);
            clear_reg("rax");
            if (ait != accessor_result.end()) reg_expr["rax"] = ait->second;
            if (wit != accessor_write.end()) reg_write_target["rax"] = wit->second;
            continue;
        }
        if (x.mnemonic != "call" && x.mnemonic != "callq") continue;

        bool preserve_call_rax = false;
        if (x.has_branch_target) {
            auto hit = helpers.find(x.branch_target);
            if (hit != helpers.end()) {
                const auto kind = hit->second;
                auto binary_op = [](HelperKind k) -> std::string {
                    switch (k) {
                        case HelperKind::AddAssign: case HelperKind::AddExprInt: return "+";
                        case HelperKind::SubAssign: case HelperKind::SubExprInt: return "-";
                        case HelperKind::MulAssign: case HelperKind::MulExprDouble: return "*";
                        case HelperKind::DivAssign: case HelperKind::DivExprDouble: return "/";
                        case HelperKind::ModAssign: case HelperKind::ModExprInt: return "%";
                        default: return {};
                    }
                };
                const std::string op = binary_op(kind);
                if (!op.empty() && reg_addr.contains("rdi")) {
                    const uint64_t dst = reg_addr["rdi"];
                    ExprState result;
                    if (kind == HelperKind::AddAssign || kind == HelperKind::SubAssign || kind == HelperKind::MulAssign || kind == HelperKind::DivAssign || kind == HelperKind::ModAssign) {
                        auto lhs = classify_slot(dst);
                        auto rhs = source_expr("rsi");
                        result = make_binary(op, lhs, rhs);
                    } else {
                        auto lhs = source_expr("rsi");
                        ExprState rhs;
                        if (kind == HelperKind::AddExprInt || kind == HelperKind::SubExprInt || kind == HelperKind::ModExprInt) {
                            if (reg_imm.contains("rdx")) {
                                rhs.kind = "number"; rhs.raw_type = 7; rhs.raw_payload = reg_imm["rdx"];
                                rhs.expression = std::to_string(static_cast<int32_t>(reg_imm["rdx"]));
                            }
                        } else if (xmm_expr.contains("xmm0")) rhs = xmm_expr["xmm0"];
                        result = make_binary(op, lhs, rhs);
                    }
                    if (expr_ready(result)) {
                        stack_expr[dst] = result;
                        reg_expr["rax"] = result;
                        preserve_call_rax = true;
                    }
                }
            }
        }

        if(reg_addr.contains("rdi") && reg_imm.contains("rsi")) {
            auto git=gml_by_va.find(reg_imm["rsi"]);
            if(git!=gml_by_va.end()) {
                ExprState m; m.kind="method"; m.expression="method(self, "+git->second+")";
                stack_expr[reg_addr["rdi"]]=std::move(m);
            }
        }

        if (reg_addr.contains("rdi") && reg_imm.contains("rdx")) {
            const uint64_t count=reg_imm["rdx"];
            if(count>0 && count<=128){
                std::vector<ExprState> elems; elems.reserve(count); bool all=true;
                const std::array<std::string,3> argregs={"rcx","r8","r9"};
                for(uint64_t ai=0;ai<count;++ai){
                    uint64_t pva=0;
                    if(ai<3){auto it=reg_imm.find(argregs[ai]);if(it!=reg_imm.end())pva=it->second;}
                    else {auto it=stack_qwords.find((ai-3)*8);if(it!=stack_qwords.end())pva=it->second;}
                    auto sit=static_values.find(pva);
                    if(!pva||sit==static_values.end()){all=false;break;}
                    elems.push_back(sit->second);
                }
                if(all){
                    ExprState arr;arr.kind="array";std::ostringstream ss;ss<<"[";
                    for(size_t ai=0;ai<elems.size();++ai){if(ai)ss<<", ";ss<<elems[ai].expression;}
                    ss<<"]";arr.expression=ss.str();reg_expr["rax"]=std::move(arr);preserve_call_rax=true;
                }
            }
        }

        if (x.has_branch_target && reg_expr.contains("rcx") && expr_ready(reg_expr["rcx"]) &&
            reg_addr.contains("rdi") && reg_addr.contains("rsi") && reg_addr.contains("rdx")) {
            if (!builtin_at.contains(x.address) && !named_at.contains(x.address)) with_target_expr = reg_expr["rcx"];
        }
        if (x.has_branch_target) {
            auto fit = native_fast_calls.find(x.branch_target);
            if (fit != native_fast_calls.end() && fit->second == "event_user" && with_target_expr && reg_imm.contains("rdx")) {
                TargetUserEventCall e; e.instruction_va=x.address; e.target=recovered_argument_from_expr(*with_target_expr);
                e.user_event=static_cast<int>(reg_imm["rdx"]); target_user_events.push_back(std::move(e));
            }
        }

        if (reg_addr.contains("r8") && reg_imm.contains("rcx") && reg_imm["rcx"] <= 32 &&
            self_regs.contains("rdi") && (!reg_imm.contains("r9") || reg_imm["r9"] == 0 || reg_addr.contains("r9"))) {
            auto callable=classify_slot(reg_addr["r8"]);
            if(expr_ready(callable) && (callable.kind=="method" || callable.kind=="variable" || callable.kind=="gml_call")) {
                DynamicValueCall dc;dc.instruction_va=x.address;
                for(auto li=local_assignments.rbegin();li!=local_assignments.rend();++li) if(li->stack_slot==reg_addr["r8"]){dc.instruction_va=li->instruction_va;break;}
                dc.callable=recovered_argument_from_expr(callable,reg_addr["r8"]);
                const int cargc=static_cast<int>(reg_imm["rcx"]); bool args_ok=true;
                if(cargc>0){
                    if(!reg_addr.contains("r9")) args_ok=false;
                    else {const uint64_t argv=reg_addr["r9"];for(int ai=0;ai<cargc;++ai){auto pit=pointer_slots.find(argv+uint64_t(ai)*8);if(pit==pointer_slots.end()){args_ok=false;break;}auto e=classify_slot(pit->second);if(!expr_ready(e)){args_ok=false;break;}dc.arguments.push_back(recovered_argument_from_expr(e,pit->second));}}
                }
                if(args_ok) dynamic_value_calls.push_back(std::move(dc));
            }
        }

        auto nit = named_at.find(x.address);
        if (nit != named_at.end()) {
            auto* nc = nit->second;
            if (nc->argc >= 0 && nc->argc <= 32 && reg_addr.contains("r8")) {
                const uint64_t argv = reg_addr["r8"];
                nc->arguments.clear();
                for (int ai = 0; ai < nc->argc; ++ai) {
                    RecoveredArgument a;
                    auto pit = pointer_slots.find(argv + uint64_t(ai) * 8);
                    if (pit != pointer_slots.end()) {
                        a.value_slot = pit->second;
                        auto e = classify_slot(a.value_slot);
                        a = recovered_argument_from_expr(e, a.value_slot);
                    }
                    if (a.expression.empty()) { a.expression = "?"; a.kind = "unknown"; }
                    nc->arguments.push_back(std::move(a));
                }
            }
        }

        if (nit != named_at.end()) {
            auto* nc = nit->second;
            bool ready = nc->argc >= 0 && static_cast<size_t>(nc->argc) == nc->arguments.size();
            for (const auto& a : nc->arguments) if (a.kind == "unknown" || a.kind == "raw" || a.expression.empty()) ready = false;
            if (ready) {
                ExprState e; e.kind = "gml_call"; e.callee = nc->name; e.children = nc->arguments;
                std::ostringstream ss; ss << nc->name << "(";
                for (size_t ai=0; ai<nc->arguments.size(); ++ai) { if (ai) ss << ", "; ss << nc->arguments[ai].expression; }
                ss << ")"; e.expression = ss.str();

                if (reg_addr.contains("rdx")) { stack_expr[reg_addr["rdx"]] = e; record_local(x.address,reg_addr["rdx"],e); }
                if (return_regs.contains("rdx")) record_return(x.address,e);
                reg_expr["rax"] = e;
                preserve_call_rax = true;
            }
        }

        auto bitcall = builtin_at.find(x.address);
        if (bitcall != builtin_at.end()) {
            auto* bc = bitcall->second;
            if (bc->argc >= 0 && bc->argc <= 32 && reg_addr.contains("r9")) {
                const uint64_t argv = reg_addr["r9"];
                bc->arguments.clear();
                for (int ai=0; ai<bc->argc; ++ai) {
                    RecoveredArgument a;
                    auto pit=pointer_slots.find(argv+uint64_t(ai)*8);
                    if(pit!=pointer_slots.end()){a.value_slot=pit->second;auto e=classify_slot(a.value_slot);a=recovered_argument_from_expr(e,a.value_slot);}
                    if(a.expression.empty()){a.expression="?";a.kind="unknown";}
                    bc->arguments.push_back(std::move(a));
                }
                if (bc->name=="instance_find" && bc->argc==2 && bc->arguments.size()==2 &&
                    bc->arguments[0].kind.rfind("resource_object",0)==0 &&
                    bc->arguments[1].kind=="unknown") {
                    bc->arguments[1].kind="number"; bc->arguments[1].expression="0";
                    bc->arguments[1].raw_type=0; bc->arguments[1].raw_payload=0;
                }
            }
            bool builtin_expr_ready = bc->argc >= 0 && static_cast<size_t>(bc->argc) == bc->arguments.size();
            if (builtin_expr_ready) {
                for (const auto& a : bc->arguments) {
                    if (a.kind == "unknown" || a.kind == "raw" || a.expression.empty()) { builtin_expr_ready = false; break; }
                }
            }
            if (builtin_expr_ready) {
                ExprState e;
                e.kind = "builtin_call";
                e.callee = bc->name;
                e.children = bc->arguments;
                std::ostringstream ss; ss << bc->name << "(";
                for (size_t ai=0; ai<bc->arguments.size(); ++ai) { if(ai) ss << ", "; ss << bc->arguments[ai].expression; }
                ss << ")"; e.expression = ss.str();
                reg_expr["rax"] = std::move(e);
                preserve_call_rax = true;
            }
        }

        if (reg_addr.contains("rdi") && reg_addr.contains("rcx") && reg_imm.contains("rdx") &&
            static_cast<uint32_t>(reg_imm["rdx"]) != 0x80000000u && reg_variable_id.contains("rsi")) {
            auto target = classify_slot(reg_addr["rdi"]);
            if (expr_ready(target)) {
                ExprState idx; idx.kind="number"; idx.raw_type=7; idx.raw_payload=reg_imm["rdx"]; idx.expression=std::to_string(static_cast<int64_t>(reg_imm["rdx"]));
                ExprState e; e.kind="instance_array_get"; e.callee=reg_variable_id["rsi"];
                e.children={recovered_argument_from_expr(target,reg_addr["rdi"]), recovered_argument_from_expr(idx)};
                e.expression=target.expression+"."+reg_variable_id["rsi"]+"["+idx.expression+"]";
                stack_expr[reg_addr["rcx"]]=e; record_local(x.address,reg_addr["rcx"],e);
            }
        }

        if (reg_variable_id.contains("rsi") && reg_addr.contains("rcx")) {
            if (reg_addr.contains("rdi") && self_rvalue_slots.contains(reg_addr["rdi"])) {
                ExprState e; e.kind="variable"; e.scope=VariableScope::Self; e.expression=scoped_text(VariableScope::Self,reg_variable_id["rsi"]);
                stack_expr[reg_addr["rcx"]]=e; record_local(x.address,reg_addr["rcx"],e);
            } else if (self_regs.contains("rdi")) {
                auto value=classify_slot(reg_addr["rcx"]);
                AccessSite synthetic; synthetic.variable=reg_variable_id["rsi"]; synthetic.scope=VariableScope::Self; synthetic.write=true;
                if (expr_ready(value)) record_variable_value(x.address,&synthetic,value);
            }
        }

        if (reg_addr.contains("rdi") && reg_addr.contains("rcx") && reg_imm.contains("rdx") &&
            static_cast<uint32_t>(reg_imm["rdx"]) == 0x80000000u && reg_variable_id.contains("rsi")) {
            auto target = classify_slot(reg_addr["rdi"]);
            auto value = classify_slot(reg_addr["rcx"]);
            if (expr_ready(target) && expr_ready(value)) {
                DynamicInstanceAssignment a; a.instruction_va=x.address; a.variable=reg_variable_id["rsi"];
                a.target=recovered_argument_from_expr(target,reg_addr["rdi"]);
                a.value=recovered_argument_from_expr(value,reg_addr["rcx"]);
                dynamic_instance_assignments.push_back(std::move(a));
            }
        }

        if (reg_write_target.contains("rdi") && x.has_branch_target) {
            auto hk = helpers.find(x.branch_target);
            if (hk != helpers.end() && hk->second == HelperKind::CopyValue) {
                auto src = source_expr("rsi");
                if (expr_ready(src)) record_variable_value(x.address, reg_write_target["rdi"], src);
            }
        }

        if (reg_addr.contains("rdi") && x.has_branch_target) {
            auto hk = helpers.find(x.branch_target);
            if (hk != helpers.end() && hk->second == HelperKind::CopyValue) {
                const uint64_t dst = reg_addr["rdi"];
                ExprState src;
                if (reg_addr.contains("rsi")) src = classify_slot(reg_addr["rsi"]);
                else if (reg_imm.contains("rsi")) src = classify_absolute(reg_imm["rsi"]);
                else if (reg_expr.contains("rsi")) src = reg_expr["rsi"];
                if (!src.expression.empty()) { stack_expr[dst] = src; record_local(x.address,dst,src); }
            }
        }
        if (return_regs.contains("rdi")) {
            ExprState src;
            if (reg_addr.contains("rsi")) src=classify_slot(reg_addr["rsi"]);
            else if (reg_imm.contains("rsi")) src=classify_absolute(reg_imm["rsi"]);
            else if (reg_expr.contains("rsi")) src=reg_expr["rsi"];
            record_return(x.address,src);
        }

        if (x.has_branch_target && reg_imm.contains("rdx")) {
            auto lhs_expr = source_expr("rdi");
            auto rhs_expr = source_expr("rsi");

            if (expr_ready(rhs_expr)) {
                bool loaded_array_length = false;
                for (size_t back=0; back<14 && i>back; ++back) {
                    const auto& q=ins[i-1-back];
                    if (q.mnemonic=="mov") {
                        std::string qd, qs;
                        if (split_mov_operands(q.operands, qd, qs) && normalize_reg(qd)=="rsi" && qs.find("[rax+0x24]")!=std::string::npos) { loaded_array_length=true; break; }
                    }
                }
                if (loaded_array_length) {
                    ExprState wrapped; wrapped.kind="builtin_call"; wrapped.callee="array_length_1d";
                    wrapped.children={recovered_argument_from_expr(rhs_expr)};
                    wrapped.expression="array_length_1d("+rhs_expr.expression+")"; rhs_expr=std::move(wrapped);
                }
            }
            bool epsilon_loaded = false;
            for (size_t back=0; back<5 && i>back; ++back) {
                const auto& q=ins[i-1-back];
                if (q.mnemonic=="movsd" && q.operands.rfind("xmm0,",0)==0) epsilon_loaded=true;
            }
            if (expr_ready(lhs_expr) && expr_ready(rhs_expr) && epsilon_loaded) {
                std::string result_reg = "rax";
                size_t t = i + 1;
                const size_t scan_end = std::min(ins.size(), i + 25);
                for (; t < scan_end; ++t) {
                    const auto& q = ins[t];
                    if (q.mnemonic == "mov") {
                        std::string dst, src;
                        if (split_mov_operands(q.operands, dst, src) && normalize_reg(src) == result_reg && is_reg_name(normalize_reg(dst)))
                            result_reg = normalize_reg(dst);
                    }
                    if (q.mnemonic == "test") {
                        std::string a, b;
                        if (split_mov_operands(q.operands, a, b) && normalize_reg(a) == result_reg && normalize_reg(b) == result_reg)
                            break;
                    }
                    if (q.mnemonic == "ret") break;
                }
                if(t<scan_end && t+1<ins.size()) {
                    const auto& br=ins[t+1];
                    if(br.has_branch_target) {
                        const uint64_t fall=t+2<ins.size()?ins[t+2].address:0;
                        if (reg_imm["rdx"] == 0 && (br.mnemonic=="je" || br.mnemonic=="jne")) {
                            ExpressionBranch b;
                            b.compare_call_va=x.address; b.branch_va=br.address; b.op="==";
                            b.lhs=recovered_argument_from_expr(lhs_expr);
                            b.rhs=recovered_argument_from_expr(rhs_expr);
                            if(br.mnemonic=="je"){b.true_target=br.branch_target;b.false_target=fall;}
                            else {b.true_target=fall;b.false_target=br.branch_target;}
                            expression_branches.push_back(std::move(b));
                        } else if (reg_imm["rdx"] == 1) {
                            std::string op;
                            if(br.mnemonic=="js"||br.mnemonic=="jl") op="<";
                            else if(br.mnemonic=="jns"||br.mnemonic=="jge") op=">=";
                            else if(br.mnemonic=="jg") op=">";
                            else if(br.mnemonic=="jle") op="<=";
                            else if(br.mnemonic=="je") op="==";
                            else if(br.mnemonic=="jne") op="!=";
                            if(!op.empty()) {
                                ExpressionBranch b;
                                b.compare_call_va=x.address; b.branch_va=br.address; b.op=op;
                                b.lhs=recovered_argument_from_expr(lhs_expr);
                                b.rhs=recovered_argument_from_expr(rhs_expr);
                                b.true_target=br.branch_target; b.false_target=fall;
                                expression_branches.push_back(std::move(b));
                            }
                        }
                    }
                }
            }
        }

        if (x.has_branch_target) {
            auto hit = helpers.find(x.branch_target);
            if (hit != helpers.end() &&
                (hit->second == HelperKind::GeInt || hit->second == HelperKind::LeInt ||
                 hit->second == HelperKind::GtInt || hit->second == HelperKind::LtInt || hit->second == HelperKind::EqInt)) {
                const auto lhs = source_expr("rdi");
                ExprState rhs;
                if (reg_expr.contains("rsi")) rhs = reg_expr["rsi"];
                else if (reg_imm.contains("rsi")) {
                    rhs.kind="number"; rhs.raw_type=7; rhs.raw_payload=reg_imm["rsi"];
                    rhs.expression=std::to_string(static_cast<int32_t>(reg_imm["rsi"]));
                }
                if (expr_ready(rhs)) {
                    bool loaded_array_length=false;
                    for(size_t back=0;back<14&&i>back;++back){
                        const auto& q=ins[i-1-back]; std::string qd,qs;
                        if(q.mnemonic=="mov" && split_mov_operands(q.operands,qd,qs) && normalize_reg(qd)=="rsi" && qs.find("[rax+0x24]")!=std::string::npos){loaded_array_length=true;break;}
                    }
                    if(loaded_array_length){
                        ExprState wrapped; wrapped.kind="builtin_call"; wrapped.callee="array_length_1d";
                        wrapped.children={recovered_argument_from_expr(rhs)}; wrapped.expression="array_length_1d("+rhs.expression+")"; rhs=std::move(wrapped);
                    }
                }
                if (expr_ready(lhs) && expr_ready(rhs)) {
                    size_t t=i+1;
                    while(t<ins.size() && t<=i+3 && !(ins[t].mnemonic=="test" && (ins[t].operands=="al,al" || ins[t].operands=="eax,eax"))) ++t;
                    if(t<ins.size() && t+1<ins.size() && t<=i+3) {
                        const auto& br=ins[t+1];
                        if((br.mnemonic=="je" || br.mnemonic=="jne") && br.has_branch_target) {
                            ExpressionBranch b;
                            b.compare_call_va=x.address; b.branch_va=br.address;
                            if(hit->second==HelperKind::GeInt) b.op=">=";
                            else if(hit->second==HelperKind::LeInt) b.op="<=";
                            else if(hit->second==HelperKind::GtInt) b.op=">";
                            else if(hit->second==HelperKind::LtInt) b.op="<";
                            else b.op="==";
                            b.lhs=recovered_argument_from_expr(lhs);
                            b.rhs=recovered_argument_from_expr(rhs);
                            const uint64_t fall=t+2<ins.size()?ins[t+2].address:0;
                            if(br.mnemonic=="jne"){b.true_target=br.branch_target;b.false_target=fall;}
                            else {b.true_target=fall;b.false_target=br.branch_target;}
                            expression_branches.push_back(std::move(b));
                        }
                    }
                }
            }
        }

        if (reg_imm.contains("rdi") && reg_addr.contains("rsi") && reg_imm.contains("rdx") && reg_imm["rdx"] == 0) {
            auto lhs = classify_slot(reg_addr["rsi"]);
            auto rhs = classify_absolute(reg_imm["rdi"]);
            if (lhs.kind == "variable" && rhs.kind == "number") {
                size_t t = i + 1;
                while (t < ins.size() && t <= i + 3 && !(ins[t].mnemonic == "test" && ins[t].operands == "eax,eax")) ++t;
                if (t < ins.size() && t + 1 < ins.size() && t <= i + 3) {
                    const auto& br = ins[t + 1];
                    if ((br.mnemonic == "je" || br.mnemonic == "jne") && br.has_branch_target) {
                        const uint64_t fall = t + 2 < ins.size() ? ins[t + 2].address : 0;
                        EqualityBranch b;
                        b.compare_call_va = x.address; b.branch_va = br.address; b.variable = lhs.expression.substr(lhs.expression.find('.') + 1);
                        b.scope = lhs.scope; b.value = std::stod(rhs.expression);
                        if (br.mnemonic == "je") { b.true_target = br.branch_target; b.false_target = fall; }
                        else { b.true_target = fall; b.false_target = br.branch_target; }
                        equality_branches.push_back(std::move(b));
                    }
                }
            }
        }

        if (x.has_branch_target && argv_regs.contains("rcx") && reg_addr.contains("rdi") &&
            reg_imm.contains("rdx") && reg_imm["rdx"] > 0 && reg_imm["rdx"] <= 32) {
            normalized_argv_ptr_slots.insert(reg_addr["rdi"] + 8);
        }

        if (preserve_call_rax) {
            auto result = reg_expr.find("rax") != reg_expr.end() ? std::optional<ExprState>(reg_expr["rax"]) : std::nullopt;
            clear_reg("rax");
            if (result) reg_expr["rax"] = std::move(*result);
        } else {
            clear_reg("rax");
        }
        clear_reg("rcx"); clear_reg("rdx"); clear_reg("rsi"); clear_reg("rdi");
        clear_reg("r8"); clear_reg("r9"); clear_reg("r10"); clear_reg("r11");
    }

    for (size_t si=2; si<sites.size(); ++si) {
        const auto& w=sites[si]; if(!w.write) continue;
        const auto& arr=sites[si-1]; const auto& idx=sites[si-2];
        if(arr.write || idx.write || w.call_index<=arr.call_index || arr.call_index<=idx.call_index) continue;
        if(w.call_index-idx.call_index>24) continue;
        size_t copy_i=ins.size(); bool element_address=false;
        for(size_t j=w.call_index+1;j<ins.size()&&j<=w.call_index+60;++j){
            if(ins[j].mnemonic=="shl" && ins[j].operands.find("0x4")!=std::string::npos) element_address=true;
            if((ins[j].mnemonic=="call"||ins[j].mnemonic=="callq")&&ins[j].has_branch_target){
                auto hk=helpers.find(ins[j].branch_target);
                if(hk!=helpers.end()&&hk->second==HelperKind::CopyValue){copy_i=j;break;}
            }
        }
        if(!element_address||copy_i==ins.size()) continue;
        ExprState ae; ae.kind="array_index";
        ExprState av; av.kind="variable"; av.scope=arr.scope; av.expression=scoped_text(arr.scope,arr.variable);
        ExprState iv; iv.kind="variable"; iv.scope=idx.scope; iv.expression=scoped_text(idx.scope,idx.variable);
        ae.children={recovered_argument_from_expr(av),recovered_argument_from_expr(iv)};
        ae.expression=av.expression+"["+iv.expression+"]";
        record_variable_value(ins[copy_i].address,&w,ae);
    }

    std::sort(equality_branches.begin(), equality_branches.end(), [](const auto& a, const auto& b){ return a.compare_call_va < b.compare_call_va; });
    equality_branches.erase(std::unique(equality_branches.begin(), equality_branches.end(), [](const auto& a, const auto& b){
        return a.compare_call_va == b.compare_call_va;
    }), equality_branches.end());
}
}

std::vector<BuiltinSymbol> discover_builtin_symbols(const ElfImage& elf) {
    struct Candidate { BuiltinSymbol sym; uint64_t registrar{}; };
    std::vector<Candidate> candidates;
    std::map<uint64_t, size_t> registrar_counts;
    const auto& d = elf.bytes();
    for (const auto& sec : elf.sections()) {
        if (!sec.executable() || sec.offset + sec.size > d.size()) continue;
        for (uint64_t o = sec.offset; o + 16 < sec.offset + sec.size; ++o) {
            if (d[o] != 0xbf || d[o + 5] != 0xbe) continue;
            const uint64_t name_va = read_u32(d, o + 1);
            const uint64_t fn_va = read_u32(d, o + 6);
            if (!elf.is_executable_va(fn_va)) continue;
            auto name = elf.cstring_at_va(name_va, 160);
            if (!name || !ascii_name(*name) || name->empty() || name->find(' ') != std::string::npos) continue;
            uint64_t call_o = 0, registrar = 0;
            int arity = 0;
            uint32_t flags = 0;
            for (uint64_t q = o + 10; q + 5 <= std::min(sec.offset + sec.size, o + 40); ++q) {
                if (d[q] == 0xba && q + 5 <= d.size()) arity = static_cast<int32_t>(read_u32(d, q + 1));
                if (d[q] == 0xb9 && q + 5 <= d.size()) flags = read_u32(d, q + 1);
                if (d[q] == 0xe8 && q + 5 <= d.size()) {
                    const auto qva = elf.offset_to_va(q);
                    if (!qva) break;
                    registrar = uint64_t(int64_t(*qva + 5) + read_i32(d, q + 1));
                    call_o = q;
                    break;
                }
            }
            if (!call_o || !elf.is_executable_va(registrar)) continue;
            candidates.push_back({BuiltinSymbol{*name, fn_va, arity, flags}, registrar});
            ++registrar_counts[registrar];
            o = call_o;
        }
    }
    uint64_t best_registrar = 0; size_t best_count = 0;
    for (const auto& [r,c] : registrar_counts) if (c > best_count) { best_registrar=r; best_count=c; }
    std::vector<BuiltinSymbol> out;
    if (best_count < 16) return out;
    for (const auto& c : candidates) if (c.registrar == best_registrar) out.push_back(c.sym);
    std::sort(out.begin(), out.end(), [](const auto& a,const auto& b){return a.name<b.name;});
    out.erase(std::unique(out.begin(), out.end(), [](const auto&a,const auto&b){return a.name==b.name&&a.function_va==b.function_va;}),out.end());
    return out;
}

std::vector<VariableSlot> discover_variable_slots(const ElfImage& elf) {
    std::vector<VariableSlot> out;
    const auto& d = elf.bytes();
    for (const auto& s : elf.sections()) {
        if (!s.writable() || s.type == 8 || s.offset + s.size > d.size()) continue;
        for (uint64_t o = (s.offset + 7) & ~uint64_t(7); o + 16 <= s.offset + s.size; o += 8) {
            uint64_t name_va = elf.read_u64(o);
            auto name = elf.cstring_at_va(name_va, 256);
            if (!name || !ascii_name(*name)) continue;
            const uint32_t id = read_u32(d, o + 8);
            if (id != 0xffffffffu && id != 0u) continue;
            auto id_va = elf.offset_to_va(o + 8);
            if (!id_va) continue;
            if (name->rfind("gml_", 0) == 0) continue;
            out.push_back({*name, name_va, *id_va, id});
            o += 8;
        }
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b){ return a.id_va < b.id_va; });
    out.erase(std::unique(out.begin(), out.end(), [](const auto& a, const auto& b){ return a.id_va == b.id_va; }), out.end());
    return out;
}

std::unordered_map<uint64_t, uint64_t> recover_fde_starts(const ElfImage& elf) {
    const Section* hdr = nullptr;
    for (const auto& s : elf.sections()) if (s.name == ".eh_frame_hdr") hdr = &s;
    if (!hdr || hdr->size < 12) return {};
    const auto& d = elf.bytes();
    const uint64_t o = hdr->offset;
    if (o + hdr->size > d.size()) return {};
    if (d[o] != 1 || d[o + 1] != 0x1b || d[o + 2] != 0x03 || d[o + 3] != 0x3b) return {};
    const uint32_t count = read_u32(d, o + 8);
    if (12ull + uint64_t(count) * 8ull > hdr->size) return {};
    std::unordered_map<uint64_t, uint64_t> out;
    uint64_t p = o + 12;
    for (uint32_t i = 0; i < count; ++i, p += 8) {
        const int32_t start_rel = read_i32(d, p);
        const int32_t fde_rel = read_i32(d, p + 4);
        const uint64_t start = uint64_t(int64_t(hdr->address) + start_rel);
        const uint64_t fde = uint64_t(int64_t(hdr->address) + fde_rel);
        if (elf.is_executable_va(start) && elf.is_allocated_va(fde)) out[start] = fde;
    }
    return out;
}

std::vector<BuiltinCall> recover_generic_builtin_calls(
    const std::vector<Instruction>& ins,
    const std::unordered_map<uint64_t,std::string>& variable_by_id,
    const std::unordered_map<std::string,BuiltinSymbol>& builtin_by_name) {
    std::vector<BuiltinCall> out;
    for(size_t i=0;i<ins.size();++i){
        const auto& x=ins[i];
        if(x.mnemonic!="mov" || !x.has_referenced_va) continue;
        std::string dst,src; if(!split_mov_operands(x.operands,dst,src) || normalize_reg(dst)!="r8") continue;
        auto vit=variable_by_id.find(x.referenced_va); if(vit==variable_by_id.end()) continue;
        auto bit=builtin_by_name.find(vit->second); if(bit==builtin_by_name.end()) continue;
        int argc=-1;
        for(size_t j=i+1;j<ins.size()&&j<=i+10;++j){
            const auto& q=ins[j];
            if(q.mnemonic=="mov"){
                std::string a,b;if(split_mov_operands(q.operands,a,b)&&normalize_reg(a)=="rcx"){
                    uint64_t imm=0;if(parse_immediate(b,imm))argc=static_cast<int>(imm);
                }
                if(j>i+1 && split_mov_operands(q.operands,a,b) && normalize_reg(a)=="r8" && q.has_referenced_va) break;
            } else if(q.mnemonic=="xor") {
                std::string a,b;if(split_mov_operands(q.operands,a,b)&&normalize_reg(a)=="rcx"&&normalize_reg(b)=="rcx")argc=0;
            }
            if((q.mnemonic=="call"||q.mnemonic=="callq")&&q.has_branch_target){
                const auto& bs=bit->second;
                BuiltinCall c;c.instruction_va=q.address;c.target=q.branch_target;c.name=bs.name;c.declared_arity=bs.declared_arity;c.flags=bs.flags;c.argc=argc;out.push_back(std::move(c));break;
            }
        }
    }
    std::sort(out.begin(),out.end(),[](const auto&a,const auto&b){return a.instruction_va<b.instruction_va;});
    out.erase(std::unique(out.begin(),out.end(),[](const auto&a,const auto&b){return a.instruction_va==b.instruction_va&&a.name==b.name;}),out.end());
    return out;
}

std::vector<BuiltinTruthyBranch> recover_native_fast_truthy_branches(
    const std::vector<Instruction>& ins,
    const std::unordered_map<uint64_t, std::string>& native_fast_calls,
    uint64_t function_end) {
    std::vector<BuiltinTruthyBranch> out;
    for (size_t i = 0; i < ins.size(); ++i) {
        const auto& call = ins[i];
        if ((call.mnemonic != "call" && call.mnemonic != "callq") || !call.has_branch_target) continue;
        auto fit = native_fast_calls.find(call.branch_target);
        if (fit == native_fast_calls.end()) continue;
        uint64_t imm = 0; bool got = false;
        for (size_t back = 0; back < 6 && i > back; ++back) {
            std::string d, src;
            const auto& q = ins[i - 1 - back];
            if (q.mnemonic == "mov" && split_mov_operands(q.operands,d,src) && normalize_reg(d)=="rdi" && parse_immediate(src,imm)) { got=true; break; }
        }
        if (!got) continue;
        size_t test_i = SIZE_MAX;
        for (size_t j=i+1; j<ins.size() && j<=i+3; ++j) {
            if (ins[j].mnemonic=="test" && (ins[j].operands=="al,al" || ins[j].operands=="eax,eax")) { test_i=j; break; }
        }
        if (test_i==SIZE_MAX || test_i+1>=ins.size()) continue;
        const auto& br=ins[test_i+1];
        if ((br.mnemonic!="je" && br.mnemonic!="jne") || !br.has_branch_target) continue;
        const uint64_t fall=test_i+2<ins.size()?ins[test_i+2].address:function_end;
        BuiltinTruthyBranch b;
        b.call_va=call.address; b.branch_va=br.address; b.builtin=fit->second; b.argc=1;
        RecoveredArgument a; a.kind="number"; a.expression=std::to_string(static_cast<long long>(imm)); a.raw_type=7; a.raw_payload=imm;
        b.arguments.push_back(std::move(a));
        if (br.mnemonic=="je") { b.true_target=fall; b.false_target=br.branch_target; }
        else { b.true_target=br.branch_target; b.false_target=fall; }
        out.push_back(std::move(b));
    }
    std::sort(out.begin(),out.end(),[](const auto&a,const auto&b){return a.branch_va<b.branch_va;});
    out.erase(std::unique(out.begin(),out.end(),[](const auto&a,const auto&b){return a.branch_va==b.branch_va;}),out.end());
    return out;
}

std::vector<BuiltinTruthyBranch> recover_local_builtin_truthy_branches(
    const std::vector<Instruction>& ins,
    const std::vector<LocalValueAssignment>& locals,
    uint64_t function_end) {
    std::vector<BuiltinTruthyBranch> out;
    for (size_t i = 0; i + 3 < ins.size(); ++i) {
        if (ins[i].mnemonic != "lea") continue;
        std::string dst, src;
        if (!split_mov_operands(ins[i].operands, dst, src) || normalize_reg(dst) != "rdi") continue;
        auto slot = rsp_mem_offset(src);
        if (!slot) continue;
        const auto& call = ins[i + 1];
        if ((call.mnemonic != "call" && call.mnemonic != "callq") || !call.has_branch_target) continue;
        if (ins[i + 2].mnemonic != "test" || ins[i + 2].operands != "al,al") continue;
        const auto& br = ins[i + 3];
        if ((br.mnemonic != "je" && br.mnemonic != "jne") || !br.has_branch_target) continue;

        const LocalValueAssignment* best = nullptr;
        for (const auto& l : locals) {
            if (l.stack_slot != *slot || l.instruction_va >= ins[i].address) continue;
            if (!best || l.instruction_va > best->instruction_va) best = &l;
        }
        if (!best || best->value.kind != "builtin_call" || best->value.callee.empty()) continue;

        BuiltinTruthyBranch b;
        b.call_va = call.address;
        b.branch_va = br.address;
        b.builtin = best->value.callee;
        b.argc = static_cast<int>(best->value.children.size());
        b.arguments = best->value.children;
        const uint64_t fall = i + 4 < ins.size() ? ins[i + 4].address : function_end;
        if (br.mnemonic == "je") { b.true_target = fall; b.false_target = br.branch_target; }
        else { b.true_target = br.branch_target; b.false_target = fall; }
        out.push_back(std::move(b));
    }
    return out;
}

std::vector<BuiltinTruthyBranch> recover_builtin_truthy_branches(
    const std::vector<Instruction>& ins,
    const std::vector<BuiltinCall>& calls,
    uint64_t function_end) {
    std::vector<BuiltinTruthyBranch> out;
    std::unordered_map<uint64_t, size_t> index_by_va;
    for (size_t i = 0; i < ins.size(); ++i) index_by_va[ins[i].address] = i;
    for (const auto& c : calls) {
        auto it = index_by_va.find(c.instruction_va);
        if (it == index_by_va.end()) continue;
        const size_t ci = it->second;

        size_t truth_call = SIZE_MAX, test_i = SIZE_MAX;
        bool moved_result = false;
        for (size_t j = ci + 1; j < ins.size() && j <= ci + 7; ++j) {
            std::string d, src;
            if (ins[j].mnemonic == "mov" && split_mov_operands(ins[j].operands, d, src) &&
                normalize_reg(d) == "rdi" && normalize_reg(src) == "rax") {
                moved_result = true;
                continue;
            }
            if (moved_result && (ins[j].mnemonic == "call" || ins[j].mnemonic == "callq") && ins[j].has_branch_target) {
                truth_call = j;
                continue;
            }
            if (truth_call != SIZE_MAX && ins[j].mnemonic == "test" && ins[j].operands == "al,al") {
                test_i = j;
                break;
            }

            if ((ins[j].mnemonic == "call" || ins[j].mnemonic == "callq") && !moved_result) break;
        }
        if (test_i == SIZE_MAX || test_i + 1 >= ins.size()) continue;
        const auto& br = ins[test_i + 1];
        if ((br.mnemonic != "je" && br.mnemonic != "jne") || !br.has_branch_target) continue;
        const uint64_t fall = test_i + 2 < ins.size() ? ins[test_i + 2].address : function_end;
        BuiltinTruthyBranch b;
        b.call_va = c.instruction_va;
        b.branch_va = br.address;
        b.builtin = c.name;
        b.argc = c.argc;
        b.arguments = c.arguments;
        if (br.mnemonic == "je") { b.true_target = fall; b.false_target = br.branch_target; }
        else { b.true_target = br.branch_target; b.false_target = fall; }
        out.push_back(std::move(b));
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b){ return a.branch_va < b.branch_va; });
    out.erase(std::unique(out.begin(), out.end(), [](const auto& a, const auto& b){ return a.branch_va == b.branch_va; }), out.end());
    return out;
}

std::vector<BuiltinResultAssignment> recover_builtin_result_assignments(
    const std::vector<Instruction>& ins,
    const std::vector<AccessSite>& sites,
    const std::vector<BuiltinCall>& calls) {
    std::vector<BuiltinResultAssignment> out;
    std::unordered_map<uint64_t,size_t> index_by_va;
    for(size_t i=0;i<ins.size();++i) index_by_va[ins[i].address]=i;
    for(const auto& a:sites){
        if(!a.write || a.scope==VariableScope::Unknown) continue;
        std::string dstreg;
        for(size_t j=a.call_index+1;j<ins.size()&&j<=a.call_index+3;++j){
            std::string d,src;
            if(ins[j].mnemonic=="mov"&&split_mov_operands(ins[j].operands,d,src)&&normalize_reg(src)=="rax"&&is_reg_name(normalize_reg(d))){dstreg=normalize_reg(d);break;}
        }
        if(dstreg.empty()) continue;
        for(const auto& c:calls){
            auto cit=index_by_va.find(c.instruction_va); if(cit==index_by_va.end()||cit->second<=a.call_index) continue;
            const size_t ci=cit->second; if(ci-a.call_index>96) continue;
            bool clobbered=false;
            for(size_t k=a.call_index+1;k<ci;++k){std::string d,src;if(ins[k].mnemonic=="mov"&&split_mov_operands(ins[k].operands,d,src)&&normalize_reg(d)==dstreg&&normalize_reg(src)!="rax"){clobbered=true;break;}}
            if(clobbered) continue;
            bool saw_dst=false,saw_src=false,saw_copy=false;
            for(size_t k=ci+1;k<ins.size()&&k<=ci+6;++k){
                std::string d,src;
                if(ins[k].mnemonic=="mov"&&split_mov_operands(ins[k].operands,d,src)){
                    if(normalize_reg(d)=="rdi"&&normalize_reg(src)==dstreg)saw_dst=true;
                    if(normalize_reg(d)=="rsi"&&normalize_reg(src)=="rax")saw_src=true;
                }
                if((ins[k].mnemonic=="call"||ins[k].mnemonic=="callq")&&saw_dst&&saw_src){saw_copy=true;break;}
            }
            if(!saw_copy) continue;
            BuiltinResultAssignment r;
            r.instruction_va=c.instruction_va;r.target=a.variable;r.target_scope=a.scope;r.builtin=c.name;r.argc=c.argc;r.arguments=c.arguments;
            out.push_back(std::move(r)); break;
        }
    }
    std::sort(out.begin(),out.end(),[](const auto&a,const auto&b){return a.instruction_va<b.instruction_va;});
    out.erase(std::unique(out.begin(),out.end(),[](const auto&a,const auto&b){return a.instruction_va==b.instruction_va&&a.target==b.target;}),out.end());
    return out;
}

uint64_t owning_block(const std::vector<BasicBlock>& blocks, uint64_t va) {
    for (const auto& b : blocks) if (va >= b.start && va < b.end) return b.start;
    return 0;
}

void assign_statement_blocks(FunctionAnalysis& fn) {
    for (auto& x : fn.variable_copies) x.owner_block = owning_block(fn.blocks, x.instruction_va);
    for (auto& x : fn.constant_assignments) x.owner_block = owning_block(fn.blocks, x.instruction_va);
    for (auto& x : fn.boolean_assignments) x.owner_block = owning_block(fn.blocks, x.instruction_va);
    for (auto& x : fn.named_calls) x.owner_block = owning_block(fn.blocks, x.instruction_va);
    for (auto& x : fn.builtin_calls) x.owner_block = owning_block(fn.blocks, x.instruction_va);
    for (auto& x : fn.builtin_result_assignments) x.owner_block = owning_block(fn.blocks, x.instruction_va);
    for (auto& x : fn.variable_value_assignments) x.owner_block = owning_block(fn.blocks, x.instruction_va);
    for (auto& x : fn.compound_assignments) x.owner_block = owning_block(fn.blocks, x.instruction_va);
    for (auto& x : fn.dynamic_value_calls) x.owner_block = owning_block(fn.blocks, x.instruction_va);
    for (auto& x : fn.target_user_events) x.owner_block = owning_block(fn.blocks, x.instruction_va);
}

CodeAnalysis analyze_code(const std::filesystem::path& executable, const ElfImage& elf, const IffInfo& iff, const Discovery& discovery) {
    CodeAnalysis out;
    out.variables = discover_variable_slots(elf);
    out.builtins = discover_builtin_symbols(elf);
    const auto static_values = discover_static_values(elf, iff);
    std::unordered_map<uint64_t, std::string> variable_by_id;
    for (const auto& v : out.variables) variable_by_id[v.id_va] = v.name;

    auto fde = recover_fde_starts(elf);
    std::vector<uint64_t> starts;
    starts.reserve(fde.size());
    for (const auto& [s, _] : fde) starts.push_back(s);
    std::sort(starts.begin(), starts.end());

    std::unordered_map<uint64_t, std::string> gml_by_va;
    std::unordered_map<uint64_t, BuiltinSymbol> builtin_by_va;
    std::unordered_map<std::string, BuiltinSymbol> builtin_by_name;
    for (const auto& b : out.builtins) { builtin_by_va[b.function_va] = b; builtin_by_name[b.name] = b; }
    std::unordered_map<uint64_t, std::string> native_fast_calls;
    auto kfit = builtin_by_name.find("keyboard_check");
    if (kfit != builtin_by_name.end()) native_fast_calls[kfit->second.function_va + 0xa0] = "keyboard_check";
    auto eufit = builtin_by_name.find("event_user");
    if (eufit != builtin_by_name.end() && eufit->second.function_va >= 0x10) native_fast_calls[eufit->second.function_va - 0x10] = "event_user";
    auto eifit = builtin_by_name.find("event_inherited");
    if (eifit != builtin_by_name.end() && eifit->second.function_va >= 0x90) native_fast_calls[eifit->second.function_va - 0x90] = "event_inherited";
    std::unordered_map<uint64_t, HelperKind> helper_cache;
    for (const auto& g : discovery.functions) gml_by_va[g.function_va] = g.name;
    if (std::getenv("KWIK_YYC_DUMP_BUILTINS")) {
        for (const auto& b : out.builtins) std::fprintf(stderr, "[yyc-builtin] 0x%llx %s\n", (unsigned long long)b.function_va, b.name.c_str());
    }

    const char* analyze_filter = std::getenv("KWIK_YYC_ANALYZE_FUNCTION");
    for (const auto& g : discovery.functions) {
        if (analyze_filter && *analyze_filter && g.name != analyze_filter) continue;
        uint64_t end = 0;
        auto it = std::upper_bound(starts.begin(), starts.end(), g.function_va);
        if (fde.contains(g.function_va) && it != starts.end()) end = *it;
        if (!end) {
            uint64_t best = UINT64_MAX;
            for (const auto& h : discovery.functions) if (h.function_va > g.function_va) best = std::min(best, h.function_va);
            if (best != UINT64_MAX) end = best;
        }
        if (!end || end <= g.function_va) end = g.function_va + 0x1000;

        const bool profile = std::getenv("KWIK_YYC_PROFILE") != nullptr;
        const auto profile_start = std::chrono::steady_clock::now();
        auto profile_mark = [&](const char* stage) {
            if (!profile) return;
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - profile_start).count();
            std::fprintf(stderr, "[yyc-profile] %s %s: %lld ms\\n",
                g.name.c_str(), stage, static_cast<long long>(ms));
        };
        FunctionAnalysis fn;
        fn.name = g.name;
        fn.start = g.function_va;
        fn.end = end;
        fn.instructions = disassemble_range(executable, fn.start, fn.end);
        if (!fn.instructions.empty()) {
            fn.start = fn.instructions.front().address;
            fn.blocks = build_cfg(fn.instructions, fn.start, fn.end);
        }
        for (const auto& x : fn.instructions) {
            if ((x.mnemonic == "call" || x.mnemonic == "callq") && x.has_branch_target) {
                fn.direct_calls.push_back(x.branch_target);
                auto git = gml_by_va.find(x.branch_target);
                if (git != gml_by_va.end()) {
                    int argc = -1;
                    const size_t xi = static_cast<size_t>(&x - fn.instructions.data());
                    for (size_t back = xi; back > 0 && xi - back < 12; --back) {
                        const auto& q = fn.instructions[back - 1];
                        if (q.mnemonic == "mov" && q.operands.rfind("ecx,0x", 0) == 0) { argc = static_cast<int>(parse_hex(q.operands.substr(6))); break; }
                        if (q.mnemonic == "mov" && q.operands.rfind("ecx,", 0) == 0) {
                            const auto imm = q.operands.substr(4);
                            if (!imm.empty() && std::isdigit(static_cast<unsigned char>(imm[0]))) { argc = std::atoi(imm.c_str()); break; }
                        }
                    }
                    fn.named_calls.push_back({x.address, x.branch_target, git->second, argc, {}});
                } else {
                    auto bit = builtin_by_va.find(x.branch_target);
                    if (bit != builtin_by_va.end()) { BuiltinCall c; c.instruction_va=x.address;c.target=x.branch_target;c.name=bit->second.name;c.declared_arity=bit->second.declared_arity;c.flags=bit->second.flags;fn.builtin_calls.push_back(std::move(c)); }
                    else {
                        auto fit=native_fast_calls.find(x.branch_target);
                        if(fit!=native_fast_calls.end() && fit->second=="event_inherited") {
                            auto src=builtin_by_name.find("event_inherited");
                            BuiltinCall c; c.instruction_va=x.address;c.target=x.branch_target;c.name="event_inherited";c.argc=0;
                            if(src!=builtin_by_name.end()){c.declared_arity=src->second.declared_arity;c.flags=src->second.flags;}
                            fn.builtin_calls.push_back(std::move(c));
                        }
                    }
                }
            }
            if (x.has_referenced_va) {
                auto vit = variable_by_id.find(x.referenced_va);
                if (vit != variable_by_id.end()) fn.variable_uses.push_back({x.address, x.referenced_va, vit->second});
            }
        }
        { auto indirect=recover_generic_builtin_calls(fn.instructions,variable_by_id,builtin_by_name); fn.builtin_calls.insert(fn.builtin_calls.end(),indirect.begin(),indirect.end()); }
        std::sort(fn.builtin_calls.begin(),fn.builtin_calls.end(),[](const auto&a,const auto&b){return a.instruction_va<b.instruction_va;});
        fn.builtin_calls.erase(std::unique(fn.builtin_calls.begin(),fn.builtin_calls.end(),[](const auto&a,const auto&b){return a.instruction_va==b.instruction_va&&a.name==b.name;}),fn.builtin_calls.end());
        std::sort(fn.direct_calls.begin(), fn.direct_calls.end());
        fn.direct_calls.erase(std::unique(fn.direct_calls.begin(), fn.direct_calls.end()), fn.direct_calls.end());
        for (const auto target : fn.direct_calls) {
            if (!elf.is_executable_va(target) || helper_cache.contains(target) || gml_by_va.contains(target)) continue;
            uint64_t nearest = UINT64_MAX;
            for (const auto& gg : discovery.functions) {
                const uint64_t dist = target > gg.function_va ? target - gg.function_va : gg.function_va - target;
                nearest = std::min(nearest, dist);
            }

            if (nearest > 0x40000) { helper_cache[target] = HelperKind::Unknown; continue; }
            helper_cache[target] = classify_helper(executable, target);
            if (std::getenv("KWIK_YYC_PROFILE")) std::fprintf(stderr, "[yyc-helper] 0x%llx kind=%d\n", static_cast<unsigned long long>(target), static_cast<int>(helper_cache[target]));
        }
        profile_mark("helper classification");
        auto access_sites = recover_access_sites(fn.instructions, variable_by_id);
        for (const auto& a : access_sites) fn.scoped_variable_uses.push_back({fn.instructions[a.id_index].address, fn.instructions[a.call_index].address, a.id_va, a.variable, a.scope, a.write});
        fn.variable_copies = recover_variable_copies(fn.instructions, access_sites);
        fn.compound_assignments = recover_compound_assignments(fn.instructions, access_sites, helper_cache, elf);
        fn.relational_branches = recover_relational_branches(fn.instructions, access_sites, helper_cache, fn.end);
        fn.constant_assignments = recover_constant_assignments(fn.instructions, variable_by_id);
        fn.boolean_assignments = recover_boolean_assignments(fn.instructions, variable_by_id);
        auto infer_write_scope = [&](uint64_t at, const std::string& name) {
            VariableScope best = VariableScope::Unknown;
            uint64_t best_dist = UINT64_MAX;
            for (const auto& a : fn.scoped_variable_uses) {
                if (!a.write || a.name != name || a.scope == VariableScope::Unknown) continue;
                const uint64_t d = a.instruction_va > at ? a.instruction_va - at : at - a.instruction_va;
                if (d < best_dist && d <= 0x80) { best_dist = d; best = a.scope; }
            }
            return best;
        };
        auto fallback_variable_scope = [&](const std::string& name) {
            VariableScope only = VariableScope::Unknown;
            for (const auto& a : fn.scoped_variable_uses) {
                if (a.name != name || a.scope == VariableScope::Unknown) continue;
                if (only == VariableScope::Unknown) only = a.scope;
                else if (only != a.scope) return VariableScope::Unknown;
            }
            return only;
        };
        for (auto& c : fn.constant_assignments) { c.scope = infer_write_scope(c.instruction_va, c.variable); if (c.scope == VariableScope::Unknown) c.scope = fallback_variable_scope(c.variable); }
        for (auto& c : fn.boolean_assignments) { c.scope = infer_write_scope(c.instruction_va, c.variable); if (c.scope == VariableScope::Unknown) c.scope = fallback_variable_scope(c.variable); }
        fn.truthy_branches = recover_truthy_branches(fn.instructions, variable_by_id, fn.end);
        for (auto& b : fn.truthy_branches) {
            for (const auto& a : fn.scoped_variable_uses) if (!a.write && a.instruction_va == b.variable_read_va && a.name == b.variable) { b.scope = a.scope; break; }
        }
        profile_mark("access/assignment recovery");
        recover_call_arguments_and_equalities(fn.instructions, access_sites, fn.named_calls, fn.builtin_calls, fn.equality_branches, fn.expression_branches, fn.local_assignments, fn.return_values, fn.variable_value_assignments, fn.dynamic_instance_assignments, fn.dynamic_value_calls, fn.target_user_events, variable_by_id, iff, static_values, gml_by_va, helper_cache, native_fast_calls, elf);
        fn.builtin_truthy_branches = recover_builtin_truthy_branches(fn.instructions, fn.builtin_calls, fn.end);
        { auto local_branches = recover_local_builtin_truthy_branches(fn.instructions, fn.local_assignments, fn.end);
          fn.builtin_truthy_branches.insert(fn.builtin_truthy_branches.end(), local_branches.begin(), local_branches.end());
          auto fast_branches = recover_native_fast_truthy_branches(fn.instructions, native_fast_calls, fn.end);
          fn.builtin_truthy_branches.insert(fn.builtin_truthy_branches.end(), fast_branches.begin(), fast_branches.end());
          std::sort(fn.builtin_truthy_branches.begin(),fn.builtin_truthy_branches.end(),[](const auto&a,const auto&b){return a.branch_va<b.branch_va;});
          fn.builtin_truthy_branches.erase(std::unique(fn.builtin_truthy_branches.begin(),fn.builtin_truthy_branches.end(),[](const auto&a,const auto&b){return a.branch_va==b.branch_va;}),fn.builtin_truthy_branches.end()); }
        fn.builtin_result_assignments = recover_builtin_result_assignments(fn.instructions, access_sites, fn.builtin_calls);
        profile_mark("call arguments / expressions");
        fn.switches = recover_switches(fn.instructions, fn.equality_branches);
        fn.structured_ifs = recover_structured_ifs(fn);
        fn.structured_switches = recover_structured_switches(fn);
        fn.structured_loops = recover_structured_loops(fn);
        fn.short_circuits = recover_short_circuits(fn);
        profile_mark("CFG structuring");
        assign_statement_blocks(fn);
        for (auto& x : fn.local_assignments) x.owner_block = owning_block(fn.blocks, x.instruction_va);
        for (auto& x : fn.return_values) x.owner_block = owning_block(fn.blocks, x.instruction_va);
        for (auto& x : fn.dynamic_instance_assignments) x.owner_block = owning_block(fn.blocks, x.instruction_va);
        for (auto& x : fn.dynamic_value_calls) x.owner_block = owning_block(fn.blocks, x.instruction_va);
        if (!fn.relational_branches.empty()) {
            std::set<uint64_t> relational_branch_vas;
            for (const auto& b : fn.relational_branches) relational_branch_vas.insert(b.branch_va);
            fn.truthy_branches.erase(std::remove_if(fn.truthy_branches.begin(), fn.truthy_branches.end(), [&](const auto& b){ return relational_branch_vas.contains(b.branch_va); }), fn.truthy_branches.end());
        }
        if (!fn.expression_branches.empty()) {
            std::set<uint64_t> expression_branch_vas;
            for (const auto& b : fn.expression_branches) expression_branch_vas.insert(b.branch_va);
            fn.truthy_branches.erase(std::remove_if(fn.truthy_branches.begin(), fn.truthy_branches.end(), [&](const auto& b){ return expression_branch_vas.contains(b.branch_va); }), fn.truthy_branches.end());
            fn.builtin_truthy_branches.erase(std::remove_if(fn.builtin_truthy_branches.begin(), fn.builtin_truthy_branches.end(), [&](const auto& b){ return expression_branch_vas.contains(b.branch_va); }), fn.builtin_truthy_branches.end());
        }
        out.functions.push_back(std::move(fn));
    }
    return out;
}
}
