#include "kwik_yyc/analysis.hpp"
#include "kwik_yyc/elf.hpp"
#include "kwik_yyc/iff.hpp"
#include "kwik_yyc/yyc.hpp"
#include "kwik_yyc/emitter.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace kwik::yyc;
static void usage(){std::cerr<<"usage: kwik-yyc <yyc-executable> <game.unx|data.win> <output-dir> [--manifest-only]\n";}
int main(int argc,char**argv){
    try{
        if(argc<4){usage();return 2;}
        std::filesystem::path exe=argv[1], data=argv[2], out=argv[3];
        bool manifest_only=false; for(int i=4;i<argc;++i) if(std::string(argv[i])=="--manifest-only") manifest_only=true;
        std::cout<<"kwik-yyc: reading ELF64 x86-64 executable\n";
        ElfImage elf(exe);
        auto iff=parse_game_data(data);
        auto discovery=discover_yyc_functions(elf);
        size_t scripts=0,objects=0,rooms=0,other=0;
        for(auto&g:discovery.functions){switch(g.kind){case GmlKind::Script:++scripts;break;case GmlKind::ObjectEvent:++objects;break;case GmlKind::Room:++rooms;break;default:++other;}}
        std::cout<<"entry: 0x"<<std::hex<<elf.entry()<<std::dec<<"\n";
        std::cout<<"IFF chunks: "<<iff.chunks.size()<<" (CODE="<<(iff.has("CODE")?"yes":"no")<<", FUNC="<<(iff.has("FUNC")?"yes":"no")<<", VARI="<<(iff.has("VARI")?"yes":"no")<<")\n";
        std::cout<<"YYC GML entries: "<<discovery.functions.size()<<" [scripts="<<scripts<<", object-events="<<objects<<", rooms="<<rooms<<", other="<<other<<"]\n";
        if(discovery.functions.empty()) throw std::runtime_error("no valid YYC registration records were recovered");
        std::filesystem::create_directories(out);
        if(manifest_only) emit_manifest(out/"yyc_manifest.json",elf,iff,discovery,nullptr);
        else {
            std::cout<<"analyzing native YYC code with objdump\n";
            auto analysis=analyze_code(exe,elf,iff,discovery);
            size_t uses=0,scoped_uses=0,var_copies=0,compound_assignments=0,numeric_assignments=0,bool_assignments=0,blocks=0,named_calls=0,builtin_calls=0,call_args=0,known_call_args=0,emittable_calls=0,truthy_branches=0,builtin_truthy_branches=0,expression_branches=0,equality_branches=0,relational_branches=0,switches=0,structured_ifs=0,structured_switches=0,structured_loops=0,short_circuits=0;
            for(const auto&fn:analysis.functions){
                uses+=fn.variable_uses.size(); scoped_uses+=fn.scoped_variable_uses.size(); var_copies+=fn.variable_copies.size(); compound_assignments+=fn.compound_assignments.size();
                numeric_assignments+=fn.constant_assignments.size();
                bool_assignments+=fn.boolean_assignments.size();
                blocks+=fn.blocks.size();
                named_calls+=fn.named_calls.size(); builtin_calls+=fn.builtin_calls.size(); for(const auto& c:fn.named_calls) {
                    call_args+=c.arguments.size(); bool ready=c.argc>=0 && static_cast<size_t>(c.argc)==c.arguments.size();
                    for(const auto& a:c.arguments){const bool known=a.kind!="unknown"&&a.kind!="raw";if(known)++known_call_args;else ready=false;}
                    if(ready)++emittable_calls;
                }
                truthy_branches+=fn.truthy_branches.size(); builtin_truthy_branches+=fn.builtin_truthy_branches.size(); expression_branches+=fn.expression_branches.size(); equality_branches+=fn.equality_branches.size(); relational_branches+=fn.relational_branches.size(); switches+=fn.switches.size(); structured_ifs+=fn.structured_ifs.size(); structured_switches+=fn.structured_switches.size(); structured_loops+=fn.structured_loops.size(); short_circuits+=fn.short_circuits.size();
            }
            std::cout<<"YYC variables: "<<analysis.variables.size()<<", runner builtins: "<<analysis.builtins.size()<<"\n";
            std::cout<<"CFG blocks: "<<blocks<<", variable refs: "<<uses
                     <<", scoped refs: "<<scoped_uses<<", variable copies: "<<var_copies<<", compound assignments: "<<compound_assignments<<", numeric assignments: "<<numeric_assignments
                     <<", boolean assignments: "<<bool_assignments
                     <<", named GML calls: "<<named_calls<<", named builtin calls: "<<builtin_calls<<", call args: "<<known_call_args<<"/"<<call_args<<" understood, emittable calls: "<<emittable_calls
                     <<", truthy branches: "<<truthy_branches<<", builtin truthy branches: "<<builtin_truthy_branches<<", expression branches: "<<expression_branches<<", equality branches: "<<equality_branches<<", relational branches: "<<relational_branches<<", switches: "<<switches<<", structured ifs: "<<structured_ifs<<", structured switches: "<<structured_switches<<", structured loops: "<<structured_loops<<", short-circuits: "<<short_circuits<<"\n";
            emit_project(out,exe,data,elf,iff,discovery,analysis);
        }
        for(size_t i=0;i<discovery.functions.size() && i<8;++i)
            std::cout<<"  0x"<<std::hex<<discovery.functions[i].function_va<<std::dec<<"  "<<discovery.functions[i].name<<"\n";
        if(discovery.functions.size()>8) std::cout<<"  ...\n";
        std::cout<<"wrote "<<out.string()<<"\n";
        return 0;
    }catch(const std::exception&e){std::cerr<<"kwik-yyc: error: "<<e.what()<<"\n";return 1;}
}
