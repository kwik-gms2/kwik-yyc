#include "kwik_yyc/yyc.hpp"
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>

namespace kwik::yyc {
namespace {
bool starts_gml(const std::vector<uint8_t>& d, uint64_t o) {
    static constexpr char p[]="gml_";
    return o+4<=d.size() && std::memcmp(d.data()+o,p,4)==0;
}
GmlKind classify(const std::string& n) {
    if(n.rfind("gml_Script_",0)==0) return GmlKind::Script;
    if(n.rfind("gml_Object_",0)==0) return GmlKind::ObjectEvent;
    if(n.rfind("gml_Room_",0)==0 || n.find("_gml_Room_")!=std::string::npos) return GmlKind::Room;
    return GmlKind::Other;
}
}
const char* kind_name(GmlKind k) {
    switch(k){case GmlKind::Script:return "script";case GmlKind::ObjectEvent:return "object_event";case GmlKind::Room:return "room";default:return "other";}
}
Discovery discover_yyc_functions(const ElfImage& elf) {
    const auto& d=elf.bytes();
    std::map<uint64_t,std::string> names;
    for(const auto& s: elf.sections()) {
        if(!s.allocated() || s.executable() || s.type==8 || s.offset+s.size>d.size()) continue;
        for(uint64_t o=s.offset; o+5<s.offset+s.size; ++o) {
            if(!starts_gml(d,o)) continue;
            std::string n;
            for(uint64_t p=o; p<s.offset+s.size && n.size()<1024; ++p) {
                const auto c=d[p]; if(!c) break;
                if(c<0x20 || c>0x7e){n.clear(); break;} n.push_back(char(c));
            }
            if(n.size()>4) if(auto va=elf.offset_to_va(o)) names[*va]=std::move(n);
            o += n.empty()?0:n.size();
        }
    }
    if(names.empty()) throw std::runtime_error("no gml_* strings found; this does not look like a supported YYC executable");

    std::vector<GmlFunction> found;
    std::set<std::pair<uint64_t,uint64_t>> seen;
    for(const auto& s: elf.sections()) {
        if(!s.writable() || s.type==8 || s.offset+s.size>d.size()) continue;
        const uint64_t end=s.offset+s.size;
        for(uint64_t o=(s.offset+7)&~uint64_t(7); o+24<=end; o+=8) {
            const auto name_va=elf.read_u64(o);
            auto it=names.find(name_va); if(it==names.end()) continue;
            const auto fn=elf.read_u64(o+8);
            const auto meta=elf.read_u64(o+16);
            if(!elf.is_executable_va(fn)) continue;
            if(meta && !elf.is_allocated_va(meta)) continue;
            if(!seen.insert({name_va,fn}).second) continue;
            found.push_back({it->second,name_va,fn,meta,o,classify(it->second)});
        }
    }
    std::sort(found.begin(),found.end(),[](const auto&a,const auto&b){return a.table_offset<b.table_offset;});
    Discovery out; out.functions=std::move(found);
    if(!out.functions.empty()) {
        out.table_begin_offset=out.functions.front().table_offset;
        out.table_end_offset=out.functions.back().table_offset+24;
    }
    return out;
}
}
