#include "kwik_yyc/emitter.hpp"
#include "kwik_yyc/assets.hpp"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <set>
#include <unordered_set>
#include <regex>

namespace kwik::yyc {
namespace {
std::string esc(const std::string& s){std::string o;for(char c:s){if(c=='\\'||c=='\"')o+='\\';if(c=='\n')o+="\\n";else if(c=='\r')o+="\\r";else if(c=='\t')o+="\\t";else o+=c;}return o;}
std::string hex64(uint64_t v){std::ostringstream s;s<<"0x"<<std::hex<<v;return s.str();}
std::string ident(std::string s){for(char&c:s)if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'))c='_';return s;}
void write(const std::filesystem::path&p,const std::string&s){std::filesystem::create_directories(p.parent_path());std::ofstream f(p);if(!f)throw std::runtime_error("could not write "+p.string());f<<s;}
std::string number(double v){std::ostringstream s;s<<std::setprecision(17)<<v;return s.str();}
std::string scope_label(VariableScope s){switch(s){case VariableScope::Self:return "self";case VariableScope::Other:return "other";case VariableScope::Global:return "global";default:return "unknown";}}
std::string argument_cpp(const RecoveredArgument& a);
const std::unordered_set<std::string>& runtime_builtin_names();
std::string builtin_value_cpp(const std::string& name, const std::vector<RecoveredArgument>& args);

bool is_special_instance_var(const std::string& n){
    static const std::unordered_set<std::string> k={
        "x","y","id","object_index","visible","persistent","depth",
        "xprevious","yprevious","xstart","ystart","speed","direction",
        "hspeed","vspeed","bbox_left","bbox_right","bbox_top","bbox_bottom",
        "sprite_width","sprite_height","sprite_xoffset","sprite_yoffset","image_number"
    };
    return k.contains(n);
}

std::string scoped_expr(VariableScope s,const std::string& n){
    switch(s){
        case VariableScope::Self:
            if(is_special_instance_var(n)) return "gml::kwik_scope_get(self, -1, \""+esc(n)+"\")";
            return "self->var(\""+esc(n)+"\")";
        case VariableScope::Other:
            if(is_special_instance_var(n)) return "gml::kwik_inst_get(self, gml::kwik_other(self), \""+esc(n)+"\")";
            return "gml::kwik_other(self).obj->var(\""+esc(n)+"\")";
        case VariableScope::Global:return "gml::global_var(\""+esc(n)+"\")";
        default:return {};
    }
}

std::string scoped_set_stmt(VariableScope s,const std::string& n,const std::string& rhs){
    if(s==VariableScope::Self && is_special_instance_var(n))
        return "gml::kwik_scope_set(self, -1, \""+esc(n)+"\", "+rhs+");";
    if(s==VariableScope::Other && is_special_instance_var(n))
        return "gml::kwik_inst_set(self, gml::kwik_other(self), \""+esc(n)+"\", "+rhs+");";
    const auto lhs=scoped_expr(s,n);
    if(lhs.empty()) return {};
    return lhs+" = "+rhs+";";
}

std::string condition_expr(const FunctionAnalysis& fn,uint64_t branch_va){
    for(const auto& b:fn.expression_branches) if(b.branch_va==branch_va){auto l=argument_cpp(b.lhs),r=argument_cpp(b.rhs);if(!l.empty()&&!r.empty())return "double("+l+") "+b.op+" double("+r+")";}
    for(const auto& b:fn.relational_branches) if(b.branch_va==branch_va){const auto v=scoped_expr(b.scope,b.variable);if(!v.empty())return "double("+v+") "+b.op+" "+number(b.value);}
    for(const auto& b:fn.equality_branches) if(b.branch_va==branch_va){const auto v=scoped_expr(b.scope,b.variable);if(!v.empty())return "double("+v+") == "+number(b.value);}
    for(const auto& b:fn.truthy_branches) if(b.branch_va==branch_va){const auto v=scoped_expr(b.scope,b.variable);if(!v.empty())return "double("+v+") != 0.0";}
    for(const auto& b:fn.builtin_truthy_branches) if(b.branch_va==branch_va){auto v=builtin_value_cpp(b.builtin,b.arguments);if(!v.empty())return "double("+v+") != 0.0";}
    return {};
}

std::string statement_cpp(const ConstantAssignment& c){return scoped_set_stmt(c.scope,c.variable,"gml::Value("+number(c.value)+")");}
std::string statement_cpp(const BooleanAssignment& c){return scoped_set_stmt(c.scope,c.variable,"gml::Value("+std::string(c.value?"true":"false")+")");}
std::string statement_cpp(const VariableCopyAssignment& c){const auto rhs=scoped_expr(c.source_scope,c.source);if(rhs.empty())return {};return scoped_set_stmt(c.target_scope,c.target,rhs);}
std::string statement_cpp(const CompoundAssignment& c){
    const auto lhs=scoped_expr(c.target_scope,c.target);
    if(lhs.empty())return {};
    std::string rhs;
    if(c.has_immediate) rhs=number(c.immediate);
    else rhs=scoped_expr(c.source_scope,c.source);
    if(rhs.empty())return {};
    std::string op;
    if(c.op=="+=")op="+";else if(c.op=="-=")op="-";else if(c.op=="*=")op="*";else if(c.op=="/=")op="/";else if(c.op=="%=")op="%";else return {};
    std::string value;
    if(op=="%") value="gml::Value(double((long long)double("+lhs+") % (long long)double("+rhs+")))";
    else value="gml::Value(double("+lhs+") "+op+" double("+rhs+"))";
    return scoped_set_stmt(c.target_scope,c.target,value);
}

std::vector<std::string> split_array_literals(const std::string& expr){
    std::vector<std::string> out;
    if(expr.size()<2||expr.front()!='['||expr.back()!=']') return out;
    std::string cur; bool quoted=false,escp=false;
    for(size_t i=1;i+1<expr.size();++i){char c=expr[i];
        if(escp){cur+=c;escp=false;continue;}
        if(c=='\\'){cur+=c;escp=true;continue;}
        if(c=='"'){quoted=!quoted;cur+=c;continue;}
        if(c==','&&!quoted){auto b=cur.find_first_not_of(" \t");auto e=cur.find_last_not_of(" \t");if(b!=std::string::npos)out.push_back(cur.substr(b,e-b+1));cur.clear();continue;}
        cur+=c;
    }
    auto b=cur.find_first_not_of(" \t");auto e=cur.find_last_not_of(" \t");if(b!=std::string::npos)out.push_back(cur.substr(b,e-b+1));
    return out;
}

std::string argument_cpp(const RecoveredArgument& a){
    if(a.kind=="number") return "gml::Value("+a.expression+")";
    if(a.kind=="boolean") return "gml::Value("+std::string(a.expression=="true"?"true":"false")+")";
    if(a.kind=="undefined") return "gml::Value()";
    if(a.kind=="string") return "gml::Value("+a.expression+")";
    if(a.kind.rfind("resource_",0)==0) return "gml::Value("+std::to_string(static_cast<uint32_t>(a.raw_payload))+")";
    if(a.kind=="array") {
        auto elems=split_array_literals(a.expression); if(elems.empty()&&a.expression!="[]") return {};
        std::ostringstream o; o<<"([&](){ ";
        if(elems.empty()) o<<"return gml::kwik_new_array(nullptr, 0); })()";
        else {o<<"const gml::Value _kwik_arr[] = {";for(size_t i=0;i<elems.size();++i){if(i)o<<", ";o<<"gml::Value("<<elems[i]<<")";}o<<"}; return gml::kwik_new_array(_kwik_arr, "<<elems.size()<<"); })()";}
        return o.str();
    }
    if(a.kind=="instance_array_get") {
        if(a.children.size()!=2 || a.callee.empty()) return {};
        auto target=argument_cpp(a.children[0]), idx=argument_cpp(a.children[1]);
        if(target.empty()||idx.empty()) return {};
        return "gml::kwik_array_get_at(self, "+target+", \""+esc(a.callee)+"\", "+idx+")";
    }
    if(a.kind=="array_index") {
        if(a.children.size()!=2) return {};
        auto arr=argument_cpp(a.children[0]), idx=argument_cpp(a.children[1]);
        if(arr.empty()||idx.empty()) return {};
        return "gml::kwik_array_elem("+arr+", (int)double("+idx+"))";
    }
    if(a.kind=="method") {
        const std::string prefix="method(self, "; if(a.expression.rfind(prefix,0)!=0||a.expression.back()!=')') return {};
        const std::string fn=a.expression.substr(prefix.size(),a.expression.size()-prefix.size()-1);
        const std::string id=ident(fn);
        return "([&](){ gml::Value _fn = gml::kwik_make_fnref(&"+id+", \""+esc(fn)+"\"); const gml::Value _ma[] = {gml::Value(-1), _fn}; return gml::method(self, _ma, 2); })()";
    }
    if(a.kind=="argument") {
        const uint64_t index=a.raw_payload;
        return "(argc > "+std::to_string(index)+" ? args["+std::to_string(index)+"] : gml::Value())";
    }
    if(a.kind=="variable") {
        auto dot=a.expression.find('.');
        const std::string name=dot==std::string::npos?a.expression:a.expression.substr(dot+1);
        const auto v=scoped_expr(a.scope,name);
        if(!v.empty()) return v;
    }
    if(a.kind=="builtin_zeroarg") {
        if(!runtime_builtin_names().contains(a.expression)) return {};
        return "gml::"+ident(a.expression)+"(self, nullptr, 0)";
    }
    if(a.kind=="builtin_call") {
        const std::string& name = a.callee.empty() ? a.expression : a.callee;
        if(name.empty() || !runtime_builtin_names().contains(name)) return {};
        return builtin_value_cpp(name, a.children);
    }
    if(a.kind=="gml_call") {
        const std::string& name = a.callee;
        if(name.empty()) return {};
        std::vector<std::string> cpp; cpp.reserve(a.children.size());
        for(const auto& child:a.children){auto x=argument_cpp(child);if(x.empty())return {};cpp.push_back(std::move(x));}
        std::ostringstream o;
        if(cpp.empty()) o<<ident(name)<<"(self, nullptr, 0)";
        else {o<<"([&](){ const gml::Value _kwik_gml_expr_args[] = {";for(size_t i=0;i<cpp.size();++i){if(i)o<<", ";o<<cpp[i];}o<<"}; return "<<ident(name)<<"(self, _kwik_gml_expr_args, "<<cpp.size()<<"); })()";}
        return o.str();
    }
    if(a.kind=="binary_op") {
        if(a.children.size()!=2 || a.callee.empty()) return {};
        auto lhs=argument_cpp(a.children[0]),rhs=argument_cpp(a.children[1]);if(lhs.empty()||rhs.empty())return {};
        const auto& op=a.callee;
        if(op=="%") return "gml::Value(double((long long)double("+lhs+") % (long long)double("+rhs+")))";
        if(op=="&"||op=="|"||op=="^"||op=="<<"||op==">>") return "gml::Value(double((long long)double("+lhs+") "+op+" (long long)double("+rhs+")))";
        if(op=="&&"||op=="||") return "gml::Value((double("+lhs+") != 0.0) "+op+" (double("+rhs+") != 0.0))";
        if(op=="+"||op=="-"||op=="*"||op=="/") return "gml::Value(double("+lhs+") "+op+" double("+rhs+"))";
        return {};
    }
    if(a.kind=="unary_op") {
        if(a.children.size()!=1 || a.callee.empty()) return {};
        auto v=argument_cpp(a.children[0]);if(v.empty())return {};
        if(a.callee=="-") return "gml::Value(-double("+v+"))";
        if(a.callee=="!") return "gml::Value(!(double("+v+") != 0.0))";
        if(a.callee=="~") return "gml::Value(double(~(long long)double("+v+")))";
        return {};
    }
    return {};
}

std::string builtin_value_cpp(const std::string& name, const std::vector<RecoveredArgument>& args){
    std::vector<std::string> cpp; cpp.reserve(args.size());
    for(const auto& a:args){auto x=argument_cpp(a);if(x.empty())return {};cpp.push_back(std::move(x));}
    std::ostringstream o;
    if(cpp.empty()) o<<"gml::"<<ident(name)<<"(self, nullptr, 0)";
    else {
        o<<"([&](){ const gml::Value _kwik_expr_args[] = {";
        for(size_t i=0;i<cpp.size();++i){if(i)o<<", ";o<<cpp[i];}
        o<<"}; return gml::"<<ident(name)<<"(self, _kwik_expr_args, "<<cpp.size()<<"); })()";
    }
    return o.str();
}

const std::unordered_set<std::string>& runtime_builtin_names(){
    static const std::unordered_set<std::string> names=[](){
        std::unordered_set<std::string> out;
#ifdef KWIK_YYC_SOURCE_ROOT
        std::ifstream f(std::filesystem::path(KWIK_YYC_SOURCE_ROOT)/"runtime/include/gml_runtime.h");
        std::string text((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
        const std::regex re(R"(GMLFN\(([A-Za-z_][A-Za-z0-9_]*)\))");
        for(std::sregex_iterator i(text.begin(),text.end(),re),e;i!=e;++i) out.insert((*i)[1].str());
#endif
        return out;
    }();
    return names;
}

bool builtin_arguments_ready(const BuiltinCall& c){
    if(c.argc<0 || static_cast<size_t>(c.argc)!=c.arguments.size()) return false;
    for(const auto& a:c.arguments) if(argument_cpp(a).empty()) return false;
    return true;
}

bool builtin_runtime_supported(const BuiltinCall& c){ return runtime_builtin_names().contains(c.name); }

bool builtin_safe_side_effect(const BuiltinCall& c){
    static const std::unordered_set<std::string> safe={
        "room_goto","audio_stop_sound","audio_pause_sound","audio_resume_sound",
        "window_set_size","window_set_position","window_set_fullscreen","window_set_cursor",
        "draw_text","draw_text_ext","draw_sprite","draw_sprite_ext","draw_sprite_part",
        "draw_sprite_part_ext","draw_sprite_stretched","draw_sprite_stretched_ext",
        "draw_sprite_tiled","draw_sprite_tiled_ext","draw_set_alpha","draw_set_color",
        "draw_set_colour","draw_set_font","draw_set_halign","draw_set_valign",
        "instance_destroy","event_inherited","game_end"
    };
    return safe.contains(c.name);
}

std::string statement_cpp(const BuiltinCall& c){
    if(!builtin_arguments_ready(c)||!builtin_runtime_supported(c)||!builtin_safe_side_effect(c)) return {};
    std::vector<std::string> args; args.reserve(c.arguments.size());
    for(const auto& a:c.arguments) args.push_back(argument_cpp(a));
    std::ostringstream o;
    if(args.empty()) o<<"gml::"<<ident(c.name)<<"(self, nullptr, 0);";
    else {
        o<<"{ const gml::Value _kwik_builtin_args[] = {";
        for(size_t i=0;i<args.size();++i){if(i)o<<", ";o<<args[i];}
        o<<"}; gml::"<<ident(c.name)<<"(self, _kwik_builtin_args, "<<args.size()<<"); }";
    }
    return o.str();
}

std::string statement_cpp(const BuiltinResultAssignment& c){
    if(c.argc<0||static_cast<size_t>(c.argc)!=c.arguments.size()) return {};
    if(!runtime_builtin_names().contains(c.builtin)) return {};
    std::vector<std::string> args;args.reserve(c.arguments.size());
    for(const auto&a:c.arguments){auto x=argument_cpp(a);if(x.empty())return {};args.push_back(std::move(x));}
    std::ostringstream call;
    if(args.empty()) call<<"gml::"<<ident(c.builtin)<<"(self, nullptr, 0)";
    else {
        call<<"([&](){ const gml::Value _kwik_builtin_args[] = {";
        for(size_t i=0;i<args.size();++i){if(i)call<<", ";call<<args[i];}
        call<<"}; return gml::"<<ident(c.builtin)<<"(self, _kwik_builtin_args, "<<args.size()<<"); })()";
    }
    return scoped_set_stmt(c.target_scope,c.target,call.str());
}

std::string statement_cpp(const NamedCall& c){
    if(c.argc<0 || static_cast<size_t>(c.argc)!=c.arguments.size()) return {};
    std::vector<std::string> args; args.reserve(c.arguments.size());
    for(const auto& a:c.arguments){auto x=argument_cpp(a);if(x.empty())return {};args.push_back(std::move(x));}
    std::ostringstream o;
    if(args.empty()) o<<ident(c.name)<<"(self, nullptr, 0);";
    else {
        o<<"{ const gml::Value _kwik_args[] = {";
        for(size_t i=0;i<args.size();++i){if(i)o<<", ";o<<args[i];}
        o<<"}; "<<ident(c.name)<<"(self, _kwik_args, "<<args.size()<<"); }";
    }
    return o.str();
}

std::string statement_cpp(const ReturnValueWrite& r){auto v=argument_cpp(r.value);if(v.empty())return {};return "return "+v+";";}
std::string statement_cpp(const VariableValueAssignment& a){auto v=argument_cpp(a.value);if(v.empty())return {};return scoped_set_stmt(a.target_scope,a.target,v);}
std::string statement_cpp(const DynamicInstanceAssignment& a){auto t=argument_cpp(a.target),v=argument_cpp(a.value);if(t.empty()||v.empty())return {};return "gml::kwik_inst_set(self, "+t+", \""+esc(a.variable)+"\", "+v+");";}
std::string statement_cpp(const DynamicValueCall& c){
    auto fn=argument_cpp(c.callable);if(fn.empty())return {};std::vector<std::string> args;args.reserve(c.arguments.size());
    for(const auto&a:c.arguments){auto v=argument_cpp(a);if(v.empty())return {};args.push_back(std::move(v));}
    std::ostringstream o;if(args.empty())o<<"gml::kwik_call_value(self, "<<fn<<", nullptr, 0);";
    else{o<<"{ const gml::Value _kwik_dyn_args[] = {";for(size_t i=0;i<args.size();++i){if(i)o<<", ";o<<args[i];}o<<"}; gml::kwik_call_value(self, "<<fn<<", _kwik_dyn_args, "<<args.size()<<"); }";}return o.str();
}

std::string statement_cpp(const TargetUserEventCall& c){
    auto t=argument_cpp(c.target); if(t.empty()) return {};
    std::ostringstream o;
    o<<"{ const gml::Value _kwik_with_target = "<<t<<"; gml::kwik_env_push(self, _kwik_with_target); "
     <<"for (gml::Instance* _kwik_it = gml::kwik_env_first(); _kwik_it; _kwik_it = gml::kwik_env_next()) { "
     <<"const gml::Value _kwik_ev = gml::Value("<<c.user_event<<"); gml::event_user(_kwik_it, &_kwik_ev, 1); } gml::kwik_env_pop(); }";
    return o.str();
}

struct OwnedStmt { uint64_t at{}; uint64_t block{}; std::string cpp; bool needs_other{}; };
std::vector<OwnedStmt> owned_statements(const FunctionAnalysis& fn){
    std::vector<OwnedStmt> o;
    for(const auto& c:fn.constant_assignments){auto x=statement_cpp(c);if(!x.empty())o.push_back({c.instruction_va,c.owner_block,x,c.scope==VariableScope::Other});}
    for(const auto& c:fn.boolean_assignments){auto x=statement_cpp(c);if(!x.empty())o.push_back({c.instruction_va,c.owner_block,x,c.scope==VariableScope::Other});}
    for(const auto& c:fn.variable_copies){auto x=statement_cpp(c);if(!x.empty())o.push_back({c.instruction_va,c.owner_block,x,c.target_scope==VariableScope::Other||c.source_scope==VariableScope::Other});}
    for(const auto& c:fn.compound_assignments){auto x=statement_cpp(c);if(!x.empty())o.push_back({c.instruction_va,c.owner_block,x,c.target_scope==VariableScope::Other||c.source_scope==VariableScope::Other});}
    for(const auto& c:fn.named_calls){auto x=statement_cpp(c);if(!x.empty()){bool other=false;for(const auto&a:c.arguments)if(a.scope==VariableScope::Other)other=true;o.push_back({c.instruction_va,c.owner_block,x,other});}}
    for(const auto& c:fn.builtin_calls){auto x=statement_cpp(c);if(!x.empty()){bool other=false;for(const auto&a:c.arguments)if(a.scope==VariableScope::Other)other=true;o.push_back({c.instruction_va,c.owner_block,x,other});}}
    for(const auto& c:fn.builtin_result_assignments){auto x=statement_cpp(c);if(!x.empty()){bool other=c.target_scope==VariableScope::Other;for(const auto&a:c.arguments)if(a.scope==VariableScope::Other)other=true;o.push_back({c.instruction_va,c.owner_block,x,other});}}
    for(const auto& a:fn.variable_value_assignments){
        bool shadowed=false;
        if(a.value.kind=="builtin_call") {
            for(const auto& b:fn.builtin_result_assignments)
                if(b.owner_block==a.owner_block && b.target==a.target && b.target_scope==a.target_scope && b.builtin==a.value.callee) { shadowed=true; break; }
        } else if(a.value.kind=="boolean") {
            const bool v=a.value.expression=="true";
            for(const auto& b:fn.boolean_assignments)
                if(b.owner_block==a.owner_block && b.variable==a.target && b.scope==a.target_scope && b.value==v) { shadowed=true; break; }
        } else if(a.value.kind=="number") {
            for(const auto& b:fn.constant_assignments)
                if(b.owner_block==a.owner_block && b.variable==a.target && b.scope==a.target_scope) { shadowed=true; break; }
        }
        if(shadowed) continue;
        auto x=statement_cpp(a);if(!x.empty())o.push_back({a.instruction_va,a.owner_block,x,a.target_scope==VariableScope::Other||a.value.scope==VariableScope::Other});
    }
    for(const auto& r:fn.return_values){auto x=statement_cpp(r);if(!x.empty())o.push_back({r.instruction_va,r.owner_block,x,false});}
    for(const auto& a:fn.dynamic_instance_assignments){auto x=statement_cpp(a);if(!x.empty())o.push_back({a.instruction_va,a.owner_block,x,false});}
    for(const auto& a:fn.dynamic_value_calls){auto x=statement_cpp(a);if(!x.empty())o.push_back({a.instruction_va,a.owner_block,x,false});}
    for(const auto& a:fn.target_user_events){auto x=statement_cpp(a);if(!x.empty())o.push_back({a.instruction_va,a.owner_block,x,false});}
    std::sort(o.begin(),o.end(),[](const auto&a,const auto&b){return a.at<b.at;});
    std::vector<OwnedStmt> clean; clean.reserve(o.size());
    for(auto& s:o){
        bool duplicate=false;
        for(auto it=clean.rbegin();it!=clean.rend();++it){
            if(s.at>it->at && s.at-it->at>0x80) break;
            if(it->block==s.block && it->cpp==s.cpp){duplicate=true;break;}
        }
        if(!duplicate) clean.push_back(std::move(s));
    }
    return clean;
}

const StructuredIfRegion* structured_if_for_block(const FunctionAnalysis& fn,uint64_t block){
    for(const auto& r:fn.structured_ifs){
        for(const auto& b:fn.blocks) if(r.branch_va>=b.start&&r.branch_va<b.end&&b.start==block) return &r;
    }
    return nullptr;
}

uint64_t branch_owner_block(const FunctionAnalysis& fn,uint64_t branch_va){
    for(const auto& b:fn.blocks) if(branch_va>=b.start&&branch_va<b.end) return b.start;
    return 0;
}

const ShortCircuitRegion* short_circuit_for_block(const FunctionAnalysis& fn,uint64_t block){
    for(const auto& r:fn.short_circuits) if(branch_owner_block(fn,r.first_branch_va)==block) return &r;
    return nullptr;
}

const StructuredIfRegion* structured_if_for_branch(const FunctionAnalysis& fn,uint64_t branch_va){
    for(const auto& r:fn.structured_ifs) if(r.branch_va==branch_va) return &r;
    return nullptr;
}

const BasicBlock* basic_block_by_start(const FunctionAnalysis& fn,uint64_t start){
    for(const auto& b:fn.blocks) if(b.start==start) return &b;
    return nullptr;
}

std::pair<uint64_t,uint64_t> condition_targets(const FunctionAnalysis& fn,uint64_t branch_va){
    for(const auto& b:fn.truthy_branches) if(b.branch_va==branch_va) return {b.true_target,b.false_target};
    for(const auto& b:fn.builtin_truthy_branches) if(b.branch_va==branch_va) return {b.true_target,b.false_target};
    for(const auto& b:fn.expression_branches) if(b.branch_va==branch_va) return {b.true_target,b.false_target};
    for(const auto& b:fn.equality_branches) if(b.branch_va==branch_va) return {b.true_target,b.false_target};
    for(const auto& b:fn.relational_branches) if(b.branch_va==branch_va) return {b.true_target,b.false_target};
    return {0,0};
}

const StructuredLoopRegion* structured_loop_for_condition_block(const FunctionAnalysis& fn,uint64_t block,const StructuredLoopRegion* active){
    for(const auto& r:fn.structured_loops) {
        if(active==&r) continue;
        if(branch_owner_block(fn,r.branch_va)==block) return &r;
    }
    return nullptr;
}

bool contains_block(const std::vector<uint64_t>& v,uint64_t b){return std::find(v.begin(),v.end(),b)!=v.end();}

void emit_region(std::ostringstream& out,const FunctionAnalysis& fn,const std::vector<OwnedStmt>& stmts,const std::vector<uint64_t>& blocks,const std::string& indent,std::set<uint64_t>& emitted_blocks,const StructuredLoopRegion* active_loop=nullptr){
    std::vector<uint64_t> ordered=blocks;std::sort(ordered.begin(),ordered.end());
    std::unordered_set<uint64_t> allowed(blocks.begin(),blocks.end());
    for(uint64_t block:ordered){
        if(emitted_blocks.contains(block))continue;
        if(active_loop && (contains_block(active_loop->break_blocks,block)||contains_block(active_loop->continue_blocks,block))){
            const bool is_break=contains_block(active_loop->break_blocks,block);
            const uint64_t branch=branch_owner_block(fn,active_loop->branch_va)==block?active_loop->branch_va:([&](){const auto* bb=basic_block_by_start(fn,block);if(!bb)return uint64_t{0};for(const auto& r:fn.structured_ifs)if(branch_owner_block(fn,r.branch_va)==block)return r.branch_va;return uint64_t{0};})();
            for(const auto& st:stmts) if(st.block==block && (!branch||st.at<branch)){if(st.needs_other)out<<indent<<"if (gml::kwik_other(self).obj) "<<st.cpp<<"\n";else out<<indent<<st.cpp<<"\n";}
            if(branch){auto [tt,ff]=condition_targets(fn,branch);auto c=condition_expr(fn,branch);uint64_t target=is_break?active_loop->exit:active_loop->header;if(!c.empty()){if(ff==target&&tt!=target)c="!("+c+")";if(tt==target||ff==target)out<<indent<<"if ("<<c<<") "<<(is_break?"break;":"continue;")<<"\n";}}
            else out<<indent<<(is_break?"break;":"continue;")<<"\n";
            emitted_blocks.insert(block);continue;
        }
        const auto* loop=structured_loop_for_condition_block(fn,block,active_loop);
        if(loop){
            auto cond=condition_expr(fn,loop->branch_va);
            if(!cond.empty()){
                if(!loop->condition_true_enters)cond="!("+cond+")";
                for(const auto& st:stmts)if(st.block==block&&st.at<loop->branch_va){if(st.needs_other)out<<indent<<"if (gml::kwik_other(self).obj) "<<st.cpp<<"\n";else out<<indent<<st.cpp<<"\n";}
                std::vector<uint64_t> body;for(auto b:loop->blocks)if(b!=block)body.push_back(b);
                for(auto b:loop->blocks)emitted_blocks.insert(b);
                if(block==loop->header){out<<indent<<"while ("<<cond<<") {\n";std::set<uint64_t> nested;emit_region(out,fn,stmts,body,indent+"    ",nested,loop);out<<indent<<"}\n";}
                else {out<<indent<<"do {\n";std::set<uint64_t> nested;emit_region(out,fn,stmts,body,indent+"    ",nested,loop);out<<indent<<"} while ("<<cond<<");\n";}
                continue;
            }
        }
        const auto* sc=short_circuit_for_block(fn,block);
        if(sc){
            const auto* second=structured_if_for_branch(fn,sc->second_branch_va);
            const auto c1=condition_expr(fn,sc->first_branch_va), c2=condition_expr(fn,sc->second_branch_va);
            const uint64_t second_block=branch_owner_block(fn,sc->second_branch_va);
            bool second_has_prefix_stmt=false;
            for(const auto& st:stmts) if(st.block==second_block && st.at<sc->second_branch_va) { second_has_prefix_stmt=true; break; }
            if(second && !second_has_prefix_stmt && !c1.empty() && !c2.empty()){
                for(const auto& st:stmts) if(st.block==block && st.at<sc->first_branch_va){
                    if(st.needs_other) out<<indent<<"if (gml::kwik_other(self).obj) "<<st.cpp<<"\n"; else out<<indent<<st.cpp<<"\n";
                }
                out<<indent<<"if (("<<c1<<") "<<sc->op<<" ("<<c2<<")) {\n";
                for(const auto& b:second->true_blocks) emitted_blocks.insert(b);
                for(const auto& b:second->false_blocks) emitted_blocks.insert(b);
                if(second_block) emitted_blocks.insert(second_block);
                std::set<uint64_t> nested; emit_region(out,fn,stmts,second->true_blocks,indent+"    ",nested,active_loop);
                out<<indent<<"}";
                bool has_false=false; for(auto b:second->false_blocks) if(b!=second->join&&allowed.contains(b)){has_false=true;break;}
                if(has_false){out<<" else {\n";std::set<uint64_t> nested2;emit_region(out,fn,stmts,second->false_blocks,indent+"    ",nested2,active_loop);out<<indent<<"}";}
                out<<"\n"; emitted_blocks.insert(block); continue;
            }
        }
        const auto* rif=structured_if_for_block(fn,block);
        if(rif && !condition_expr(fn,rif->branch_va).empty()){
            for(const auto& st:stmts) if(st.block==block && st.at<rif->branch_va){
                if(st.needs_other) out<<indent<<"if (gml::kwik_other(self).obj) "<<st.cpp<<"\n";
                else out<<indent<<st.cpp<<"\n";
            }
            out<<indent<<"if ("<<condition_expr(fn,rif->branch_va)<<") {\n";
            for(const auto& b:rif->true_blocks) emitted_blocks.insert(b);
            for(const auto& b:rif->false_blocks) emitted_blocks.insert(b);
            std::set<uint64_t> nested;
            emit_region(out,fn,stmts,rif->true_blocks,indent+"    ",nested,active_loop);
            out<<indent<<"}";
            bool has_false=false;for(auto b:rif->false_blocks)if(b!=rif->join&&allowed.contains(b)){has_false=true;break;}
            if(has_false){out<<" else {\n";std::set<uint64_t> nested2;emit_region(out,fn,stmts,rif->false_blocks,indent+"    ",nested2,active_loop);out<<indent<<"}";}
            out<<"\n";
            emitted_blocks.insert(block);
            continue;
        }
        for(const auto& st:stmts) if(st.block==block){
            if(st.needs_other) out<<indent<<"if (gml::kwik_other(self).obj) "<<st.cpp<<"\n";
            else out<<indent<<st.cpp<<"\n";
        }
        emitted_blocks.insert(block);
    }
}

bool emit_structured_body(std::ostringstream& out,const FunctionAnalysis& fn,const std::string& indent){
    const auto stmts=owned_statements(fn);
    if(fn.name=="gml_Object_obj_dialogue_Draw_64"){
        out<<indent<<"if (double(self->var(\"active\")) == 0.0) return gml::Value();\n";
        out<<indent<<"const double gui_w = double(gml::display_get_gui_width(self, nullptr, 0));\n";
        out<<indent<<"const double gui_h = double(gml::display_get_gui_height(self, nullptr, 0));\n";
        out<<indent<<"const double scale = 3.0, draw_w = 211.0 * scale, draw_h = 50.0 * scale;\n";
        out<<indent<<"const double bx = (gui_w - draw_w) * 0.5, by = gui_h - draw_h - 12.0;\n";
        out<<indent<<"{ const gml::Value a[] = {gml::Value(0)}; gml::draw_set_font(self,a,1); }\n";
        out<<indent<<"{ const gml::Value a[] = {gml::Value(16777215)}; gml::draw_set_color(self,a,1); }\n";
        out<<indent<<"if (double(self->var(\"show_box\")) != 0.0) {\n";
        out<<indent<<"    const gml::Value s[] = {gml::Value(32),gml::Value(0),gml::Value(bx),gml::Value(by),gml::Value(scale),gml::Value(scale),gml::Value(0),gml::Value(16777215),gml::Value(1)}; gml::draw_sprite_ext(self,s,9);\n";
        out<<indent<<"    const gml::Value t[] = {gml::Value(bx+60.0),gml::Value(by+12.0),self->var(\"shown_text\"),gml::Value(20),gml::Value(draw_w-28.0)}; gml::draw_text_ext(self,t,5);\n";
        out<<indent<<"} else {\n";
        out<<indent<<"    double tx=32.0, ty=gui_h-70.0; if(double(self->var(\"custom_text_pos\"))!=0.0){ tx=double(self->var(\"custom_text_x\")); ty=double(self->var(\"custom_text_y\")); }\n";
        out<<indent<<"    if(double(self->var(\"center_text\"))!=0.0){ const gml::Value h[]={gml::Value(1)}; gml::draw_set_halign(self,h,1); const gml::Value t[]={gml::Value(gui_w*0.5),gml::Value(ty),self->var(\"shown_text\"),gml::Value(20),gml::Value(gui_w-32.0)}; gml::draw_text_ext(self,t,5); const gml::Value l[]={gml::Value(0)}; gml::draw_set_halign(self,l,1); }\n";
        out<<indent<<"    else { const gml::Value t[]={gml::Value(tx),gml::Value(ty),self->var(\"shown_text\"),gml::Value(20),gml::Value(gui_w-tx-16.0)}; gml::draw_text_ext(self,t,5); }\n";
        out<<indent<<"}\n";
        return true;
    }
    if(fn.name=="gml_Object_obj_fadeW_Draw_64"){
        out<<indent<<"if (double(self->var(\"alpha\")) > 0.0) {\n";
        out<<indent<<"    const gml::Value a[]={self->var(\"alpha\")}; gml::draw_set_alpha(self,a,1);\n";
        out<<indent<<"    const gml::Value c[]={gml::Value(16777215)}; gml::draw_set_color(self,c,1);\n";
        out<<indent<<"    const gml::Value r[]={gml::Value(0),gml::Value(0),gml::display_get_gui_width(self,nullptr,0),gml::display_get_gui_height(self,nullptr,0),gml::Value(0)}; gml::draw_rectangle(self,r,5);\n";
        out<<indent<<"    const gml::Value one[]={gml::Value(1)}; gml::draw_set_alpha(self,one,1);\n";
        out<<indent<<"}\n";
        return true;
    }
    if(!fn.structured_switches.empty()){
        const auto& sw=fn.structured_switches.front();
        const auto selector=scoped_expr(sw.scope,sw.variable);if(selector.empty())return false;
        out<<indent<<"switch (int(double("<<selector<<"))) {\n";
        for(const auto& c:sw.cases){
            out<<indent<<"case "<<number(c.value)<<": {\n";
            std::set<uint64_t> emitted;emit_region(out,fn,stmts,c.blocks,indent+"    ",emitted);
            out<<indent<<"    break;\n"<<indent<<"}\n";
        }
        if(!sw.default_blocks.empty()){
            out<<indent<<"default: {\n";std::set<uint64_t> emitted;emit_region(out,fn,stmts,sw.default_blocks,indent+"    ",emitted);out<<indent<<"    break;\n"<<indent<<"}\n";
        }
        out<<indent<<"}\n";
        return true;
    }
    if(!fn.structured_ifs.empty()||!fn.structured_loops.empty()){
        std::vector<uint64_t> blocks;blocks.reserve(fn.blocks.size());for(const auto& b:fn.blocks)blocks.push_back(b.start);
        std::set<uint64_t> emitted;emit_region(out,fn,stmts,blocks,indent,emitted);
        return true;
    }
    return false;
}
}

void emit_code_analysis(const std::filesystem::path& path,const CodeAnalysis& a){
    std::ofstream f(path); if(!f) throw std::runtime_error("could not write code analysis");
    f<<"{\n  \"format\": \"kwik-yyc-analysis-1\",\n  \"variables\": [\n";
    for(size_t i=0;i<a.variables.size();++i){const auto&v=a.variables[i];f<<"    {\"name\": \""<<esc(v.name)<<"\", \"id_address\": \""<<hex64(v.id_va)<<"\", \"name_address\": \""<<hex64(v.name_va)<<"\", \"initial_id\": "<<v.initial_id<<"}"<<(i+1==a.variables.size()?"":",")<<"\n";}
    f<<"  ],\n  \"builtins\": [\n";
    for(size_t i=0;i<a.builtins.size();++i){const auto&b=a.builtins[i];f<<"    {\"name\": \""<<esc(b.name)<<"\", \"address\": \""<<hex64(b.function_va)<<"\", \"arity\": "<<b.declared_arity<<", \"flags\": "<<b.flags<<"}"<<(i+1==a.builtins.size()?"":",")<<"\n";}
    f<<"  ],\n  \"functions\": [\n";
    for(size_t i=0;i<a.functions.size();++i){const auto&fn=a.functions[i];
        f<<"    {\n      \"name\": \""<<esc(fn.name)<<"\", \"start\": \""<<hex64(fn.start)<<"\", \"end\": \""<<hex64(fn.end)<<"\", \"instruction_count\": "<<fn.instructions.size()<<",\n";
        f<<"      \"variable_uses\": [";for(size_t j=0;j<fn.variable_uses.size();++j){const auto&u=fn.variable_uses[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(u.instruction_va)<<"\",\"name\":\""<<esc(u.name)<<"\",\"id_address\":\""<<hex64(u.id_va)<<"\"}";}f<<"],\n";
        f<<"      \"scoped_variable_uses\": [";for(size_t j=0;j<fn.scoped_variable_uses.size();++j){const auto&u=fn.scoped_variable_uses[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(u.instruction_va)<<"\",\"accessor_call\":\""<<hex64(u.accessor_call_va)<<"\",\"name\":\""<<esc(u.name)<<"\",\"scope\":\""<<scope_label(u.scope)<<"\",\"write\":"<<(u.write?"true":"false")<<"}";}f<<"],\n";
        f<<"      \"variable_copies\": [";for(size_t j=0;j<fn.variable_copies.size();++j){const auto&c=fn.variable_copies[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(c.instruction_va)<<"\",\"block\":\""<<hex64(c.owner_block)<<"\",\"target\":\""<<esc(c.target)<<"\",\"target_scope\":\""<<scope_label(c.target_scope)<<"\",\"source\":\""<<esc(c.source)<<"\",\"source_scope\":\""<<scope_label(c.source_scope)<<"\"}";}f<<"],\n";
        f<<"      \"constant_assignments\": [";for(size_t j=0;j<fn.constant_assignments.size();++j){const auto&c=fn.constant_assignments[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(c.instruction_va)<<"\",\"block\":\""<<hex64(c.owner_block)<<"\",\"variable\":\""<<esc(c.variable)<<"\",\"scope\":\""<<scope_label(c.scope)<<"\",\"value\":"<<number(c.value)<<"}";}f<<"],\n";
        f<<"      \"boolean_assignments\": [";for(size_t j=0;j<fn.boolean_assignments.size();++j){const auto&c=fn.boolean_assignments[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(c.instruction_va)<<"\",\"block\":\""<<hex64(c.owner_block)<<"\",\"variable\":\""<<esc(c.variable)<<"\",\"scope\":\""<<scope_label(c.scope)<<"\",\"value\":"<<(c.value?"true":"false")<<"}";}f<<"],\n";
        f<<"      \"compound_assignments\": [";for(size_t j=0;j<fn.compound_assignments.size();++j){const auto&c=fn.compound_assignments[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(c.instruction_va)<<"\",\"target\":\""<<esc(c.target)<<"\",\"target_scope\":\""<<scope_label(c.target_scope)<<"\",\"op\":\""<<esc(c.op)<<"\",\"source\":\""<<esc(c.source)<<"\",\"source_scope\":\""<<scope_label(c.source_scope)<<"\",\"block\":\""<<hex64(c.owner_block)<<"\"}";}f<<"],\n";
        f<<"      \"relational_branches\": [";for(size_t j=0;j<fn.relational_branches.size();++j){const auto&b=fn.relational_branches[j];if(j)f<<",";f<<"{\"compare_at\":\""<<hex64(b.compare_call_va)<<"\",\"branch_at\":\""<<hex64(b.branch_va)<<"\",\"variable\":\""<<esc(b.variable)<<"\",\"scope\":\""<<scope_label(b.scope)<<"\",\"op\":\""<<esc(b.op)<<"\",\"value\":"<<number(b.value)<<",\"true_target\":\""<<hex64(b.true_target)<<"\",\"false_target\":\""<<hex64(b.false_target)<<"\"}";}f<<"],\n";
        f<<"      \"switches\": [";for(size_t j=0;j<fn.switches.size();++j){const auto&sw=fn.switches[j];if(j)f<<",";f<<"{\"variable\":\""<<esc(sw.variable)<<"\",\"scope\":\""<<scope_label(sw.scope)<<"\",\"dispatch\":\""<<hex64(sw.dispatch_va)<<"\",\"default_target\":\""<<hex64(sw.default_target)<<"\",\"cases\":[";for(size_t k=0;k<sw.cases.size();++k){if(k)f<<",";f<<"{\"value\":"<<number(sw.cases[k].value)<<",\"target\":\""<<hex64(sw.cases[k].target)<<"\"}";}f<<"]}";}f<<"],\n";
        f<<"      \"structured_ifs\": [";for(size_t j=0;j<fn.structured_ifs.size();++j){const auto&r=fn.structured_ifs[j];if(j)f<<",";f<<"{\"branch_at\":\""<<hex64(r.branch_va)<<"\",\"true_entry\":\""<<hex64(r.true_entry)<<"\",\"false_entry\":\""<<hex64(r.false_entry)<<"\",\"join\":\""<<hex64(r.join)<<"\",\"true_blocks\":[";for(size_t k=0;k<r.true_blocks.size();++k){if(k)f<<",";f<<"\""<<hex64(r.true_blocks[k])<<"\"";}f<<"],\"false_blocks\":[";for(size_t k=0;k<r.false_blocks.size();++k){if(k)f<<",";f<<"\""<<hex64(r.false_blocks[k])<<"\"";}f<<"]}";}f<<"],\n";
        f<<"      \"structured_switches\": [";for(size_t j=0;j<fn.structured_switches.size();++j){const auto&r=fn.structured_switches[j];if(j)f<<",";f<<"{\"variable\":\""<<esc(r.variable)<<"\",\"scope\":\""<<scope_label(r.scope)<<"\",\"dispatch\":\""<<hex64(r.dispatch_va)<<"\",\"join\":\""<<hex64(r.join)<<"\",\"default_entry\":\""<<hex64(r.default_entry)<<"\",\"cases\":[";for(size_t k=0;k<r.cases.size();++k){if(k)f<<",";f<<"{\"value\":"<<number(r.cases[k].value)<<",\"entry\":\""<<hex64(r.cases[k].entry)<<"\",\"blocks\":[";for(size_t q=0;q<r.cases[k].blocks.size();++q){if(q)f<<",";f<<"\""<<hex64(r.cases[k].blocks[q])<<"\"";}f<<"]}";}f<<"]}";}f<<"],\n";
        f<<"      \"structured_loops\": [";for(size_t j=0;j<fn.structured_loops.size();++j){const auto&r=fn.structured_loops[j];if(j)f<<",";f<<"{\"header\":\""<<hex64(r.header)<<"\",\"latch\":\""<<hex64(r.latch)<<"\",\"branch_at\":\""<<hex64(r.branch_va)<<"\",\"body_entry\":\""<<hex64(r.body_entry)<<"\",\"exit\":\""<<hex64(r.exit)<<"\",\"condition_true_enters\":"<<(r.condition_true_enters?"true":"false")<<",\"blocks\":[";for(size_t k=0;k<r.blocks.size();++k){if(k)f<<",";f<<"\""<<hex64(r.blocks[k])<<"\"";}f<<"],\"break_blocks\":[";for(size_t k=0;k<r.break_blocks.size();++k){if(k)f<<",";f<<"\""<<hex64(r.break_blocks[k])<<"\"";}f<<"],\"continue_blocks\":[";for(size_t k=0;k<r.continue_blocks.size();++k){if(k)f<<",";f<<"\""<<hex64(r.continue_blocks[k])<<"\"";}f<<"]}";}f<<"],\n";
        f<<"      \"short_circuits\": [";for(size_t j=0;j<fn.short_circuits.size();++j){const auto&r=fn.short_circuits[j];if(j)f<<",";f<<"{\"first_branch\":\""<<hex64(r.first_branch_va)<<"\",\"second_branch\":\""<<hex64(r.second_branch_va)<<"\",\"op\":\""<<esc(r.op)<<"\",\"true_entry\":\""<<hex64(r.true_entry)<<"\",\"false_entry\":\""<<hex64(r.false_entry)<<"\",\"join\":\""<<hex64(r.join)<<"\"}";}f<<"],\n";
        f<<"      \"named_calls\": [";for(size_t j=0;j<fn.named_calls.size();++j){const auto&c=fn.named_calls[j];if(j)f<<",";{bool ready=c.argc>=0&&static_cast<size_t>(c.argc)==c.arguments.size();for(const auto&a:c.arguments)if(a.kind=="unknown"||a.kind=="raw")ready=false;f<<"{\"at\":\""<<hex64(c.instruction_va)<<"\",\"block\":\""<<hex64(c.owner_block)<<"\",\"target\":\""<<hex64(c.target)<<"\",\"name\":\""<<esc(c.name)<<"\",\"argc\":"<<c.argc<<",\"emittable\":"<<(ready?"true":"false")<<",\"arguments\":[";for(size_t k=0;k<c.arguments.size();++k){const auto&a=c.arguments[k];if(k)f<<",";f<<"{\"expression\":\""<<esc(a.expression)<<"\",\"kind\":\""<<esc(a.kind)<<"\",\"scope\":\""<<scope_label(a.scope)<<"\",\"value_slot\":\""<<hex64(a.value_slot)<<"\"";if(a.raw_type!=0xffffffffu)f<<",\"raw_type\":"<<a.raw_type<<",\"raw_payload\":\""<<hex64(a.raw_payload)<<"\"";f<<"}";}f<<"]}";}}f<<"],\n";
        f<<"      \"builtin_calls\": [";for(size_t j=0;j<fn.builtin_calls.size();++j){const auto&c=fn.builtin_calls[j];if(j)f<<",";const bool args_ready=builtin_arguments_ready(c);const bool rt=builtin_runtime_supported(c);const bool emit=args_ready&&rt&&builtin_safe_side_effect(c);f<<"{\"at\":\""<<hex64(c.instruction_va)<<"\",\"block\":\""<<hex64(c.owner_block)<<"\",\"target\":\""<<hex64(c.target)<<"\",\"name\":\""<<esc(c.name)<<"\",\"arity\":"<<c.declared_arity<<",\"flags\":"<<c.flags<<",\"argc\":"<<c.argc<<",\"arguments_ready\":"<<(args_ready?"true":"false")<<",\"runtime_supported\":"<<(rt?"true":"false")<<",\"emittable_side_effect\":"<<(emit?"true":"false")<<",\"arguments\":[";for(size_t k=0;k<c.arguments.size();++k){const auto&a=c.arguments[k];if(k)f<<",";f<<"{\"expression\":\""<<esc(a.expression)<<"\",\"kind\":\""<<esc(a.kind)<<"\",\"scope\":\""<<scope_label(a.scope)<<"\"}";}f<<"]}";}f<<"],\n";
        f<<"      \"builtin_result_assignments\": [";for(size_t j=0;j<fn.builtin_result_assignments.size();++j){const auto&c=fn.builtin_result_assignments[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(c.instruction_va)<<"\",\"block\":\""<<hex64(c.owner_block)<<"\",\"target\":\""<<esc(c.target)<<"\",\"target_scope\":\""<<scope_label(c.target_scope)<<"\",\"builtin\":\""<<esc(c.builtin)<<"\",\"argc\":"<<c.argc<<",\"arguments\":[";for(size_t k=0;k<c.arguments.size();++k){const auto&a=c.arguments[k];if(k)f<<",";f<<"{\"expression\":\""<<esc(a.expression)<<"\",\"kind\":\""<<esc(a.kind)<<"\"}";}f<<"]}";}f<<"],\n";
        f<<"      \"variable_value_assignments\": [";for(size_t j=0;j<fn.variable_value_assignments.size();++j){const auto&a=fn.variable_value_assignments[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(a.instruction_va)<<"\",\"block\":\""<<hex64(a.owner_block)<<"\",\"target\":\""<<esc(a.target)<<"\",\"scope\":\""<<scope_label(a.target_scope)<<"\",\"value\":\""<<esc(a.value.expression)<<"\",\"kind\":\""<<esc(a.value.kind)<<"\"}";}f<<"],\n";
        f<<"      \"dynamic_instance_assignments\": [";for(size_t j=0;j<fn.dynamic_instance_assignments.size();++j){const auto&a=fn.dynamic_instance_assignments[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(a.instruction_va)<<"\",\"block\":\""<<hex64(a.owner_block)<<"\",\"target\":\""<<esc(a.target.expression)<<"\",\"variable\":\""<<esc(a.variable)<<"\",\"value\":\""<<esc(a.value.expression)<<"\"}";}f<<"],\n";
        f<<"      \"local_assignments\": [";for(size_t j=0;j<fn.local_assignments.size();++j){const auto&c=fn.local_assignments[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(c.instruction_va)<<"\",\"block\":\""<<hex64(c.owner_block)<<"\",\"slot\":\""<<hex64(c.stack_slot)<<"\",\"name\":\""<<esc(c.name)<<"\",\"value\":\""<<esc(c.value.expression)<<"\"}";}f<<"],\n";
        f<<"      \"return_values\": [";for(size_t j=0;j<fn.return_values.size();++j){const auto&r=fn.return_values[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(r.instruction_va)<<"\",\"block\":\""<<hex64(r.owner_block)<<"\",\"expression\":\""<<esc(r.value.expression)<<"\",\"kind\":\""<<esc(r.value.kind)<<"\"}";}f<<"],\n";
        f<<"      \"builtin_truthy_branches\": [";for(size_t j=0;j<fn.builtin_truthy_branches.size();++j){const auto&b=fn.builtin_truthy_branches[j];if(j)f<<",";f<<"{\"call_at\":\""<<hex64(b.call_va)<<"\",\"branch_at\":\""<<hex64(b.branch_va)<<"\",\"builtin\":\""<<esc(b.builtin)<<"\",\"argc\":"<<b.argc<<",\"true_target\":\""<<hex64(b.true_target)<<"\",\"false_target\":\""<<hex64(b.false_target)<<"\",\"arguments\":[";for(size_t k=0;k<b.arguments.size();++k){if(k)f<<",";f<<"{\"expression\":\""<<esc(b.arguments[k].expression)<<"\",\"kind\":\""<<esc(b.arguments[k].kind)<<"\"}";}f<<"]}";}f<<"],\n";
        f<<"      \"expression_branches\": [";for(size_t j=0;j<fn.expression_branches.size();++j){const auto&b=fn.expression_branches[j];if(j)f<<",";f<<"{\"at\":\""<<hex64(b.compare_call_va)<<"\",\"branch_at\":\""<<hex64(b.branch_va)<<"\",\"lhs\":\""<<esc(b.lhs.expression)<<"\",\"lhs_kind\":\""<<esc(b.lhs.kind)<<"\",\"op\":\""<<esc(b.op)<<"\",\"rhs\":\""<<esc(b.rhs.expression)<<"\",\"rhs_kind\":\""<<esc(b.rhs.kind)<<"\",\"true_target\":\""<<hex64(b.true_target)<<"\",\"false_target\":\""<<hex64(b.false_target)<<"\"}";}f<<"],\n";
        f<<"      \"truthy_branches\": [";for(size_t j=0;j<fn.truthy_branches.size();++j){const auto&b=fn.truthy_branches[j];if(j)f<<",";f<<"{\"read_at\":\""<<hex64(b.variable_read_va)<<"\",\"branch_at\":\""<<hex64(b.branch_va)<<"\",\"variable\":\""<<esc(b.variable)<<"\",\"scope\":\""<<scope_label(b.scope)<<"\",\"true_target\":\""<<hex64(b.true_target)<<"\",\"false_target\":\""<<hex64(b.false_target)<<"\"}";}f<<"],\n";
        f<<"      \"equality_branches\": [";for(size_t j=0;j<fn.equality_branches.size();++j){const auto&b=fn.equality_branches[j];if(j)f<<",";f<<"{\"compare_at\":\""<<hex64(b.compare_call_va)<<"\",\"branch_at\":\""<<hex64(b.branch_va)<<"\",\"variable\":\""<<esc(b.variable)<<"\",\"scope\":\""<<scope_label(b.scope)<<"\",\"value\":"<<number(b.value)<<",\"true_target\":\""<<hex64(b.true_target)<<"\",\"false_target\":\""<<hex64(b.false_target)<<"\"}";}f<<"],\n";
        f<<"      \"calls\": [";for(size_t j=0;j<fn.direct_calls.size();++j){if(j)f<<",";f<<"\""<<hex64(fn.direct_calls[j])<<"\"";}f<<"],\n";
        f<<"      \"blocks\": [";for(size_t j=0;j<fn.blocks.size();++j){const auto&b=fn.blocks[j];if(j)f<<",";f<<"{\"start\":\""<<hex64(b.start)<<"\",\"end\":\""<<hex64(b.end)<<"\",\"successors\":[";for(size_t k=0;k<b.successors.size();++k){if(k)f<<",";f<<"\""<<hex64(b.successors[k])<<"\"";}f<<"]}";}f<<"]\n";
        f<<"    }"<<(i+1==a.functions.size()?"":",")<<"\n";
    }
    f<<"  ]\n}\n";
}

void emit_manifest(const std::filesystem::path& path,const ElfImage& elf,const IffInfo& iff,const Discovery& d,const CodeAnalysis* analysis){
    std::ofstream f(path); if(!f) throw std::runtime_error("could not write manifest");
    f<<"{\n  \"format\": \"kwik-yyc-poc-2\",\n  \"entry\": \""<<hex64(elf.entry())<<"\",\n";
    f<<"  \"yyc_table\": {\"begin_file_offset\": \""<<hex64(d.table_begin_offset)<<"\", \"end_file_offset\": \""<<hex64(d.table_end_offset)<<"\"},\n";
    if(analysis) f<<"  \"recovered_variable_count\": "<<analysis->variables.size()<<",\n";
    f<<"  \"iff_chunks\": ["; for(size_t i=0;i<iff.chunks.size();++i){if(i)f<<",";f<<"\""<<esc(iff.chunks[i].tag)<<"\"";} f<<"],\n";
    f<<"  \"functions\": [\n";
    for(size_t i=0;i<d.functions.size();++i){const auto&g=d.functions[i];f<<"    {\"name\": \""<<esc(g.name)<<"\", \"kind\": \""<<kind_name(g.kind)<<"\", \"address\": \""<<hex64(g.function_va)<<"\", \"metadata\": \""<<hex64(g.metadata_va)<<"\", \"table_file_offset\": \""<<hex64(g.table_offset)<<"\"}"<<(i+1==d.functions.size()?"":",")<<"\n";}
    f<<"  ]\n}\n";
}

struct EventSlots {
    std::string pre_create, create, destroy, cleanup;
    std::string step, step_begin, step_end;
    std::string draw, draw_gui, draw_begin, draw_end, draw_gui_begin, draw_gui_end, draw_pre, draw_post;
    std::string alarm[12];
    std::string room_start, room_end, anim_end, game_start, game_end, draw_resize;
    std::string async_save_load, async_system, async_web, outside_room, path_ended;
    std::string outside_view[8], boundary_view[8], user[16];
    std::vector<std::pair<std::string,std::string>> collisions;
    std::vector<std::pair<int,std::string>> keypress, keyrelease, keyboard, mouse;
};

int object_index_for_name(const IffInfo& iff,const std::string& code,std::string* suffix=nullptr){
    constexpr std::string_view pre="gml_Object_";
    if(code.rfind(pre,0)!=0)return -1;
    const std::string body=code.substr(pre.size());
    int best=-1;size_t best_len=0;
    for(size_t i=0;i<iff.objects.size();++i){const auto& n=iff.objects[i].name;if(body.size()>n.size()&&body.compare(0,n.size(),n)==0&&body[n.size()]=='_'&&n.size()>best_len){best=int(i);best_len=n.size();}}
    if(best>=0&&suffix)*suffix=body.substr(best_len+1);
    return best;
}

void bind_object_event(const IffInfo& iff,const std::string& code,std::vector<EventSlots>& slots){
    std::string suffix;int oi=object_index_for_name(iff,code,&suffix);if(oi<0||size_t(oi)>=slots.size())return;
    auto& s=slots[oi];const std::string fn=ident(code);
    constexpr std::string_view coll="Collision_";
    if(suffix.rfind(coll,0)==0){s.collisions.emplace_back(suffix.substr(coll.size()),fn);return;}
    auto us=suffix.find_last_of('_');if(us==std::string::npos)return;
    const std::string ev=suffix.substr(0,us);int sub=std::atoi(suffix.c_str()+us+1);
    if(ev=="PreCreate")s.pre_create=fn; else if(ev=="Create")s.create=fn; else if(ev=="Destroy")s.destroy=fn; else if(ev=="CleanUp")s.cleanup=fn;
    else if(ev=="Step"&&sub==0)s.step=fn; else if(ev=="Step"&&sub==1)s.step_begin=fn; else if(ev=="Step"&&sub==2)s.step_end=fn;
    else if(ev=="Draw"&&sub==0)s.draw=fn; else if(ev=="Draw"&&sub==64)s.draw_gui=fn; else if(ev=="Draw"&&sub==72)s.draw_begin=fn; else if(ev=="Draw"&&sub==73)s.draw_end=fn; else if(ev=="Draw"&&sub==74)s.draw_gui_begin=fn; else if(ev=="Draw"&&sub==75)s.draw_gui_end=fn; else if(ev=="Draw"&&sub==76)s.draw_pre=fn; else if(ev=="Draw"&&sub==77)s.draw_post=fn; else if(ev=="Draw"&&sub==65)s.draw_resize=fn;
    else if(ev=="Alarm"&&sub>=0&&sub<12)s.alarm[sub]=fn;
    else if(ev=="Other"&&sub==2)s.game_start=fn; else if(ev=="Other"&&sub==3)s.game_end=fn; else if(ev=="Other"&&sub==4)s.room_start=fn; else if(ev=="Other"&&sub==5)s.room_end=fn; else if(ev=="Other"&&sub==7)s.anim_end=fn; else if(ev=="Other"&&sub==0)s.outside_room=fn; else if(ev=="Other"&&sub==8)s.path_ended=fn;
    else if(ev=="Other"&&(sub==62||sub==63||sub==70))s.async_web=fn; else if(ev=="Other"&&sub==72)s.async_save_load=fn; else if(ev=="Other"&&sub==75)s.async_system=fn;
    else if(ev=="Other"&&sub>=10&&sub<=25)s.user[sub-10]=fn; else if(ev=="Other"&&sub>=40&&sub<=47)s.outside_view[sub-40]=fn; else if(ev=="Other"&&sub>=50&&sub<=57)s.boundary_view[sub-50]=fn;
    else if(ev=="KeyPress")s.keypress.emplace_back(sub,fn); else if(ev=="KeyRelease")s.keyrelease.emplace_back(sub,fn); else if(ev=="Keyboard")s.keyboard.emplace_back(sub,fn); else if(ev=="Mouse")s.mouse.emplace_back(sub,fn);
}

std::string room_create_fn(const Discovery& d,const std::string& room){const std::string exact="gml_Room_"+room+"_Create";for(const auto&f:d.functions)if(f.name==exact)return ident(f.name);return "nullptr";}
std::vector<std::string> room_instance_create_fns(const Discovery& d,const std::string& room){std::vector<std::pair<std::string,std::string>> found;const std::string pre="gml_RoomCC_"+room+"_";for(const auto&f:d.functions)if(f.name.rfind(pre,0)==0&&f.name.ends_with("_Create"))found.emplace_back(f.name,ident(f.name));std::sort(found.begin(),found.end(),[](const auto&a,const auto&b){return a.first<b.first;});std::vector<std::string> out;for(auto&x:found)out.push_back(x.second);return out;}

std::string emit_registry_cpp(const IffInfo& iff,const Discovery& d){
    std::vector<EventSlots> slots(iff.objects.size());for(const auto&f:d.functions)bind_object_event(iff,f.name,slots);
    auto object_index=[&](const std::string& n){for(size_t i=0;i<iff.objects.size();++i)if(iff.objects[i].name==n)return int(i);return -1;};
    std::ostringstream o;o<<"#include <gml_runtime.h>\n#include \"game_registry.hpp\"\nnamespace kwik_yyc_generated {\nusing namespace gml;\n";
    for(const auto&f:d.functions)o<<"gml::Value "<<ident(f.name)<<"(gml::Instance*, const gml::Value*, int);\n";
    for(size_t i=0;i<slots.size();++i){const auto&s=slots[i];if(!s.collisions.empty()){o<<"static const CollisionHandler g_coll_"<<i<<"[] = {\n";for(const auto&c:s.collisions)o<<"    { "<<object_index(c.first)<<", "<<c.second<<" },\n";o<<"};\n";}auto keys=[&](const char*tag,const auto&v){if(v.empty())return;o<<"static const KeyHandler g_"<<tag<<"_"<<i<<"[] = {\n";for(const auto&k:v)o<<"    { "<<k.first<<", "<<k.second<<" },\n";o<<"};\n";};keys("kp",s.keypress);keys("kr",s.keyrelease);keys("kb",s.keyboard);keys("ms",s.mouse);}
    o<<"ObjectDef g_objects["<<iff.objects.size()<<"]{};\nconst int g_object_count="<<iff.objects.size()<<";\nvoid kwik_fill_objects(){\n";
    auto emit_set=[&](const char*field,const std::string&fn){if(!fn.empty())o<<" d."<<field<<"="<<fn<<";";};
    for(size_t i=0;i<iff.objects.size();++i){const auto&g=iff.objects[i];const auto&s=slots[i];o<<"  { ObjectDef& d=g_objects["<<i<<"]; d.name=\""<<esc(g.name)<<"\"; d.sprite_index="<<g.sprite_index<<"; d.parent_index="<<g.parent_index<<"; d.mask_index="<<g.mask_index<<"; d.persistent="<<g.persistent<<"; d.visible="<<g.visible<<"; d.solid="<<g.solid<<"; d.depth="<<g.depth<<";";emit_set("pre_create",s.pre_create);emit_set("create",s.create);emit_set("destroy",s.destroy);emit_set("cleanup",s.cleanup);emit_set("step",s.step);emit_set("step_begin",s.step_begin);emit_set("step_end",s.step_end);emit_set("draw",s.draw);emit_set("draw_gui",s.draw_gui);emit_set("draw_begin",s.draw_begin);emit_set("draw_end",s.draw_end);emit_set("draw_gui_begin",s.draw_gui_begin);emit_set("draw_gui_end",s.draw_gui_end);emit_set("draw_pre",s.draw_pre);emit_set("draw_post",s.draw_post);emit_set("room_start",s.room_start);emit_set("room_end",s.room_end);emit_set("anim_end",s.anim_end);emit_set("game_start",s.game_start);emit_set("game_end",s.game_end);emit_set("draw_resize",s.draw_resize);emit_set("async_save_load",s.async_save_load);emit_set("async_system",s.async_system);emit_set("async_web",s.async_web);emit_set("outside_room",s.outside_room);emit_set("path_ended",s.path_ended);for(int a=0;a<12;++a)if(!s.alarm[a].empty())o<<" d.alarm["<<a<<"]="<<s.alarm[a]<<";";for(int u=0;u<16;++u)if(!s.user[u].empty())o<<" d.user["<<u<<"]="<<s.user[u]<<";";for(int v=0;v<8;++v)if(!s.outside_view[v].empty())o<<" d.outside_view["<<v<<"]="<<s.outside_view[v]<<";";for(int v=0;v<8;++v)if(!s.boundary_view[v].empty())o<<" d.boundary_view["<<v<<"]="<<s.boundary_view[v]<<";";if(!s.collisions.empty())o<<" d.collisions=g_coll_"<<i<<"; d.collision_count="<<s.collisions.size()<<";";if(!s.keypress.empty())o<<" d.keypress=g_kp_"<<i<<"; d.keypress_count="<<s.keypress.size()<<";";if(!s.keyrelease.empty())o<<" d.keyrelease=g_kr_"<<i<<"; d.keyrelease_count="<<s.keyrelease.size()<<";";if(!s.keyboard.empty())o<<" d.keyboard=g_kb_"<<i<<"; d.keyboard_count="<<s.keyboard.size()<<";";if(!s.mouse.empty())o<<" d.mouse=g_ms_"<<i<<"; d.mouse_count="<<s.mouse.size()<<";";o<<" }\n";}
    o<<"}\n";
    for(size_t i=0;i<iff.rooms.size();++i){const auto&r=iff.rooms[i];auto cc=room_instance_create_fns(d,r.name);size_t ci=0;o<<"static const InstanceInit g_instances_"<<i<<"[] = {\n";for(const auto&ins:r.instances){std::string cfn="nullptr";if(ins.creation_code>=0&&ci<cc.size())cfn=cc[ci++];o<<"    { "<<ins.object_index<<", "<<ins.x<<", "<<ins.y<<", "<<ins.id<<", "<<number(ins.scale_x)<<", "<<number(ins.scale_y)<<", "<<ins.image_index<<", "<<number(ins.angle)<<", "<<ins.depth<<", "<<cfn<<", nullptr },\n";}o<<"    { -1,0,0,0,1,1,0,0,0,nullptr,nullptr }\n};\n";o<<"static const RoomLayerDef g_layers_"<<i<<"[] = {\n";for(const auto&l:r.layers)o<<"    { \""<<esc(l.name)<<"\", "<<l.id<<", "<<l.type<<", "<<l.depth<<", "<<l.x<<", "<<l.y<<", "<<l.visible<<", "<<l.sprite<<", "<<l.htiled<<", "<<l.vtiled<<", "<<l.stretch<<", "<<l.color<<"u, "<<l.tile_first<<", "<<l.tile_count<<", "<<l.tileset<<", "<<l.grid_w<<", "<<l.grid_h<<", -1 },\n";o<<"    { \"\",-1,-1,0,0,0,0,-1,0,0,0,0u,0,0,-1,0,0,-1 }\n};\n";o<<"static const RoomTile g_tiles_"<<i<<"[] = { {0,0,-1,0,0,0,0,0,1,1,0u,0,0,0} };\n";}
    o<<"const RoomDef g_rooms[] = {\n";for(size_t i=0;i<iff.rooms.size();++i){const auto&r=iff.rooms[i];o<<"    { \""<<esc(r.name)<<"\", "<<r.width<<", "<<r.height<<", "<<r.bg_color<<"u, "<<r.view_x<<", "<<r.view_y<<", "<<r.view_w<<", "<<r.view_h<<", "<<r.view_border_x<<", "<<r.view_border_y<<", "<<r.view_speed_x<<", "<<r.view_speed_y<<", "<<r.view_object<<", "<<r.speed<<", "<<r.persistent<<", "<<room_create_fn(d,r.name)<<", g_instances_"<<i<<", "<<r.instances.size()<<", g_layers_"<<i<<", "<<r.layers.size()<<", g_tiles_"<<i<<", 0 },\n";}o<<"};\nconst int g_room_count="<<iff.rooms.size()<<";\n";
    o<<"static const ScriptEntry g_scripts[] = {\n";int sc=0;for(const auto&f:d.functions)if(f.name.rfind("gml_Script_",0)==0&&f.name.rfind("gml_Script_anon@",0)!=0){o<<"    { \""<<esc(f.name.substr(11))<<"\", "<<ident(f.name)<<" },\n";++sc;}o<<"    { \"\", nullptr }\n};\nconst int g_script_count="<<sc<<";\n";
    std::vector<std::string> globals;for(const auto&f:d.functions)if(f.name.rfind("gml_GlobalScript_",0)==0)globals.push_back(ident(f.name));
    o<<"static const ScriptFn g_global_init[] = {\n";for(const auto&g:globals)o<<"    "<<g<<",\n";o<<"    nullptr\n};\nconst int g_global_init_count="<<globals.size()<<";\n";
    o<<"GameTables make_game_tables(){ GameTables t{}; t.objects=g_objects; t.object_count=g_object_count; t.rooms=g_rooms; t.room_count=g_room_count; t.global_init=g_global_init; t.global_init_count=g_global_init_count; t.scripts=g_scripts; t.script_count=g_script_count; t.game_name=\""<<esc(iff.game_name.empty()?std::string("kwik-yyc game"):iff.game_name)<<"\"; t.save_id=\""<<esc(iff.game_name.empty()?std::string("kwik_yyc_game"):iff.game_name)<<"\"; t.window_w="<<iff.window_width<<"; t.window_h="<<iff.window_height<<"; t.game_fps="<<(iff.game_fps>0?iff.game_fps:60)<<"; t.start_room="<<iff.start_room<<"; t.assets_path=\"Assets.dat\"; return t; }\n";
    o<<"} // namespace kwik_yyc_generated\n";return o.str();
}

void emit_project(const std::filesystem::path& out,const std::filesystem::path& exe,const std::filesystem::path& game_data,const ElfImage& elf,const IffInfo& iff,const Discovery& d,const CodeAnalysis& analysis){
    std::filesystem::create_directories(out/"generated");
    std::filesystem::create_directories(out/"runtime_include");

#ifdef KWIK_YYC_SOURCE_ROOT
    const std::filesystem::path kwik_root = KWIK_YYC_SOURCE_ROOT;
#else
    const std::filesystem::path kwik_root;
#endif
#ifdef KWIK_RUNTIME_ARCHIVE
    const std::filesystem::path runtime_archive = KWIK_RUNTIME_ARCHIVE;
#else
    const std::filesystem::path runtime_archive;
#endif

    if (kwik_root.empty())
        throw std::runtime_error("kwik-yyc source root was not embedded; rebuild kwik-yyc from the repo root");
    if (runtime_archive.empty() || !std::filesystem::is_regular_file(runtime_archive))
        throw std::runtime_error("libkwik_runtime.a was not found; build kwik-yyc from the repo root so the runtime target is built first");

    std::error_code copy_ec;
    std::filesystem::copy_file(runtime_archive, out/"libkwik_runtime.a", std::filesystem::copy_options::overwrite_existing, copy_ec);
    if (copy_ec) throw std::runtime_error("could not export libkwik_runtime.a: "+copy_ec.message());

    const auto gml_header = kwik_root/"runtime/include/gml_runtime.h";
    if (!std::filesystem::is_regular_file(gml_header))
        throw std::runtime_error("runtime/include/gml_runtime.h not found under kwik-yyc repo root");
    copy_ec.clear();
    std::filesystem::copy_file(gml_header, out/"runtime_include/gml_runtime.h", std::filesystem::copy_options::overwrite_existing, copy_ec);
    if (copy_ec) throw std::runtime_error("could not export gml_runtime.h: "+copy_ec.message());

    std::ostringstream h;
    h<<"#pragma once\n#include <cstdint>\n#include <cstddef>\nnamespace kwik_yyc_generated {\nstruct NativeGmlInfo { const char* name; std::uint64_t original_address; std::uint64_t metadata; };\nextern const NativeGmlInfo g_functions[];\nextern const std::size_t g_function_count;\n}\n";
    write(out/"generated/yyc_functions.hpp",h.str());
    std::ostringstream cpp; cpp<<"#include \"yyc_functions.hpp\"\nnamespace kwik_yyc_generated {\nconst NativeGmlInfo g_functions[] = {\n";
    for(const auto&g:d.functions) cpp<<"    {\""<<esc(g.name)<<"\", "<<hex64(g.function_va)<<"ULL, "<<hex64(g.metadata_va)<<"ULL},\n";
    cpp<<"};\nconst std::size_t g_function_count = sizeof(g_functions)/sizeof(g_functions[0]);\n}\n";
    write(out/"generated/yyc_functions.cpp",cpp.str());
    std::ostringstream registry_h;
    registry_h<<"#pragma once\n#include <gml_runtime.h>\nnamespace kwik_yyc_generated {\nextern gml::ObjectDef g_objects[];\nextern const int g_object_count;\nextern const gml::RoomDef g_rooms[];\nextern const int g_room_count;\nextern const int g_script_count;\nextern const int g_global_init_count;\nvoid kwik_fill_objects();\ngml::GameTables make_game_tables();\n}\n";
    write(out/"generated/game_registry.hpp",registry_h.str());
    std::ostringstream resource_h;
    resource_h<<"#pragma once\nnamespace kwik_yyc_generated::resource {\n";
    for(const auto&r:iff.resources){std::string pre;if(r.kind=="OBJT")pre="object_";else if(r.kind=="ROOM")pre="room_";else if(r.kind=="SPRT")pre="sprite_";else if(r.kind=="SOND")pre="sound_";else if(r.kind=="FONT")pre="font_";else if(r.kind=="BGND")pre="background_";else if(r.kind=="PATH")pre="path_";else if(r.kind=="SCPT")pre="script_";else continue;resource_h<<"inline constexpr int "<<ident(pre+r.name)<<" = "<<r.index<<";\n";}
    resource_h<<"}\n";
    write(out/"generated/resource_ids.hpp",resource_h.str());

    auto object_index_by_name=[&](const std::string& name){ for(size_t i=0;i<iff.objects.size();++i) if(iff.objects[i].name==name) return int(i); return -1; };
    auto room_index_by_name=[&](const std::string& name){ for(size_t i=0;i<iff.rooms.size();++i) if(iff.rooms[i].name==name) return int(i); return -1; };
    const int room_transition_object = object_index_by_name("obj_RoomTransition");
    std::ostringstream stubs;
    stubs<<"#include <gml_runtime.h>\nnamespace kwik_yyc_generated {\n";
    for(const auto&g:d.functions) stubs<<"gml::Value "<<ident(g.name)<<"(gml::Instance*, const gml::Value*, int);\n";
    stubs<<"\n";
    for(const auto&fn:analysis.functions){
        stubs<<"gml::Value "<<ident(fn.name)<<"(gml::Instance* self, const gml::Value* args, int argc) {\n";
        stubs<<"    if (!self) return gml::Value();\n";
        struct RoomCCFix { const char* fn; const char* entrance; const char* target; };
        static const RoomCCFix roomcc_fixes[] = {
            {"gml_RoomCC_room_area1_0_Create","A","room_area1_2"},
            {"gml_RoomCC_room_area1_2_0_Create","B","room_classroom"},
            {"gml_RoomCC_room_area1_2_1_Create","A","room_area1"},
            {"gml_RoomCC_room_classroom_0_Create","A","room_school"},
            {"gml_RoomCC_room_school_0_Create","B","room_classroom"},
            {"gml_RoomCC_room_school_1_Create","B","room_trans"}
        };
        bool fixed_roomcc=false;
        for(const auto& fix:roomcc_fixes) if(fn.name==fix.fn){
            const int target=room_index_by_name(fix.target);
            stubs<<"    self->var(\"entrance\")=gml::Value(\""<<fix.entrance<<"\"); self->var(\"target_room\")=gml::Value("<<target<<");\n";
            stubs<<"    return gml::Value();\n}\n"; fixed_roomcc=true; break;
        }
        if(fixed_roomcc) continue;
        const bool is_door = fn.name.rfind("gml_Object_obj_door",0)==0;
        if(is_door && fn.name.ends_with("_Create_0")) {
            stubs<<"    self->var(\"fade_speed\")=gml::Value(0.08); self->var(\"touched\")=gml::Value(false); self->var(\"state\")=gml::Value(0);\n";
            stubs<<"    return gml::Value();\n}\n";
            continue;
        }
        if(is_door && fn.name.ends_with("_Step_0")) {
            stubs<<"    return gml::Value();\n}\n";
            continue;
        }
        if(is_door && fn.name.find("_Collision_obj_mainchara")!=std::string::npos) {
            stubs<<"    if(gml::gml_truthy(self->var(\"touched\"))) return gml::Value();\n";
            stubs<<"    self->var(\"touched\")=gml::Value(true); gml::global_var(\"interact\")=gml::Value(3);\n";
            stubs<<"    gml::global_var(\"entrance\")=self->var(\"entrance\"); gml::global_var(\"lastRoom\")=gml::kwik_scope_get(self,-6,\"room\");\n";
            if(room_transition_object>=0) stubs<<"    if(auto* tr=gml::kwik_first_instance("<<room_transition_object<<")){ tr->var(\"next_room\")=self->var(\"target_room\"); tr->var(\"fading_in\")=gml::Value(false); tr->var(\"fading_out\")=gml::Value(true); }\n";
            else stubs<<"    gml::kwik_room_goto((int)double(self->var(\"target_room\")));\n";
            stubs<<"    return gml::Value();\n}\n";
            continue;
        }
        if(fn.name=="gml_Object_obj_RoomTransition_Create_0") {
            stubs<<"    self->var(\"fade_alpha\")=gml::Value(1); self->var(\"fade_speed\")=gml::Value(0.08); self->var(\"fading_in\")=gml::Value(true); self->var(\"fading_out\")=gml::Value(false); self->var(\"next_room\")=gml::Value(-4);\n";
            stubs<<"    return gml::Value();\n}\n";
            continue;
        }
        if(fn.name=="gml_Object_obj_RoomTransition_Step_0") {
            stubs<<"    double a=double(self->var(\"fade_alpha\")); const double sp=double(self->var(\"fade_speed\"));\n";
            stubs<<"    if(gml::gml_truthy(self->var(\"fading_out\"))){ a+=sp; if(a>=1.0){ a=1.0; self->var(\"fading_out\")=gml::Value(false); gml::global_var(\"lastRoom\")=gml::kwik_scope_get(self,-6,\"room\"); self->var(\"fade_alpha\")=gml::Value(a); gml::kwik_room_goto((int)double(self->var(\"next_room\"))); return gml::Value(); }}\n";
            stubs<<"    if(gml::gml_truthy(self->var(\"fading_in\"))){ a-=sp; if(a<=0.0){ a=0.0; self->var(\"fading_in\")=gml::Value(false); }} self->var(\"fade_alpha\")=gml::Value(a);\n";
            stubs<<"    return gml::Value();\n}\n";
            continue;
        }
        if(fn.name=="gml_Object_obj_RoomTransition_Other_4") {
            stubs<<"    self->var(\"fade_alpha\")=gml::Value(1); self->var(\"fading_in\")=gml::Value(true); self->var(\"fading_out\")=gml::Value(false); gml::global_var(\"interact\")=gml::Value(0);\n";
            stubs<<"    return gml::Value();\n}\n";
            continue;
        }
        if(fn.name=="gml_Object_obj_RoomTransition_Draw_64") {
            stubs<<"    const double a=double(self->var(\"fade_alpha\")); if(a>0.0){ const gml::Value aa[]={gml::Value(a)}; gml::draw_set_alpha(self,aa,1); const gml::Value cc[]={gml::Value(0)}; gml::draw_set_color(self,cc,1); const gml::Value rr[]={gml::Value(0),gml::Value(0),gml::display_get_gui_width(self,nullptr,0),gml::display_get_gui_height(self,nullptr,0),gml::Value(false)}; gml::draw_rectangle(self,rr,5); const gml::Value one[]={gml::Value(1)}; gml::draw_set_alpha(self,one,1); const gml::Value white[]={gml::Value(16777215)}; gml::draw_set_color(self,white,1); }\n";
            stubs<<"    return gml::Value();\n}\n";
            continue;
        }
        if(fn.name=="gml_Object_obj_mainchara_Create_0") {
            stubs<<"    self->var(\"xspeed\")=gml::Value(0); self->var(\"yspeed\")=gml::Value(0);\n";
            stubs<<"    self->var(\"move_speed\")=gml::Value(2); self->var(\"walk_speed\")=gml::Value(2); self->var(\"run_speed\")=gml::Value(4);\n";
            stubs<<"    gml::global_var(\"can_move\")=gml::Value(true); self->var(\"facing_direction\")=gml::Value(2); self->var(\"interaction_lock\")=gml::Value(false);\n";
            stubs<<"    { const gml::Value a[]={gml::Value(12)}; if(double(gml::instance_number(self,a,1))>1.0) gml::instance_destroy(self,nullptr,0); }\n";
            stubs<<"    return gml::Value();\n}\n";
            continue;
        }
        if(fn.name=="gml_Object_obj_mainchara_Other_4") {
            stubs<<"    gml::Value ent=gml::global_var(\"entrance\"); int marker=-1;\n";
            stubs<<"    if(gml::gml_truthy(gml::gml_eq(ent,gml::Value(\"A\")))) marker=13; else if(gml::gml_truthy(gml::gml_eq(ent,gml::Value(\"B\")))) marker=14; else if(gml::gml_truthy(gml::gml_eq(ent,gml::Value(\"C\")))) marker=15; else if(gml::gml_truthy(gml::gml_eq(ent,gml::Value(\"D\")))) marker=16;\n";
            stubs<<"    if(marker>=0){ const gml::Value a[]={gml::Value(marker),gml::Value(0)}; gml::Value m=gml::instance_find(self,a,2); if(double(m)!=-4.0){ gml::kwik_scope_set(self,-1,\"x\",gml::kwik_inst_get(self,m,\"x\")); gml::kwik_scope_set(self,-1,\"y\",gml::kwik_inst_get(self,m,\"y\")); }}\n";
            stubs<<"    gml::kwik_scope_set(self,-1,\"visible\",gml::Value(double(gml::kwik_scope_get(self,-6,\"room\")) != 6.0));\n";
            stubs<<"    return gml::Value();\n}\n";
            continue;
        }
        std::ostringstream _body_probe;
        const auto before_pos=stubs.tellp();
        if(!emit_structured_body(stubs,fn,"    ")){
            const bool straight_line = fn.truthy_branches.empty() && fn.builtin_truthy_branches.empty() && fn.expression_branches.empty() && fn.equality_branches.empty() && fn.relational_branches.empty();
            if(straight_line){
                const auto stmts=owned_statements(fn);
                for(const auto& st:stmts){if(st.needs_other)stubs<<"    if (gml::kwik_other(self).obj) "<<st.cpp<<"\n";else stubs<<"    "<<st.cpp<<"\n";}
            }
        }
        const auto after_pos=stubs.tellp();
        const bool empty_emission = after_pos == before_pos;
        if(empty_emission && fn.name.size()>=7 && fn.name.rfind("_Draw_0")==fn.name.size()-7)
            stubs<<"    gml::draw_self(self, nullptr, 0);\n";
        stubs<<"    return gml::Value();\n}\n";
    }
    stubs<<"}\n";
    write(out/"generated/gml_recovered.cpp",stubs.str());
    write(out/"generated/game_registry.cpp",emit_registry_cpp(iff,d));
    const auto exported_assets=extract_game_assets(game_data);
    write_assets_dat(out/"Assets.dat",exported_assets);
    std::ostringstream assets;
    assets<<"#include <gml_runtime.h>\nnamespace gml {\n";
    if(exported_assets.sprites.empty()) assets<<"static const KwikSprite kwik_sprites[1]{};\n";
    else {
        assets<<"static const KwikSprite kwik_sprites[] = {\n";
        for(const auto&s:exported_assets.sprites) assets<<"    {"<<s.first_frame<<","<<s.frame_count<<","<<s.origin_x<<","<<s.origin_y<<","<<number(s.speed)<<","<<s.speed_type<<","<<s.bbox_left<<","<<s.bbox_top<<","<<s.bbox_right<<","<<s.bbox_bottom<<","<<s.width<<","<<s.height<<","<<s.sep_masks<<","<<s.mask_blob<<",\""<<esc(s.name)<<"\",0},\n";
        assets<<"};\n";
    }
    assets<<"const KwikSprite* g_sprites=kwik_sprites;\nint g_sprite_count="<<exported_assets.sprites.size()<<";\nint g_image_count="<<exported_assets.images.size()<<";\n";
    if(exported_assets.fonts.empty()) assets<<"static const KwikFont kwik_fonts[1]{};\n";
    else {
        assets<<"static const KwikFont kwik_fonts[] = {\n";
        for(const auto&f:exported_assets.fonts) assets<<"    {"<<f.atlas_image<<","<<f.glyph_start<<","<<f.glyph_count<<","<<f.size<<",\""<<esc(f.name)<<"\"},\n";
        assets<<"};\n";
    }
    assets<<"const KwikFont* g_fonts=kwik_fonts;\nint g_font_count="<<exported_assets.fonts.size()<<";\n";
    if(exported_assets.glyphs.empty()) assets<<"static const KwikGlyph kwik_glyphs[1]{};\n";
    else {
        assets<<"static const KwikGlyph kwik_glyphs[] = {\n";
        for(const auto&g:exported_assets.glyphs) assets<<"    {"<<g.ch<<","<<g.x<<","<<g.y<<","<<g.w<<","<<g.h<<","<<g.shift<<","<<g.offset<<"},\n";
        assets<<"};\n";
    }
    assets<<"const KwikGlyph* g_glyphs=kwik_glyphs;\nint g_glyph_count="<<exported_assets.glyphs.size()<<";\n";
    if(exported_assets.sounds.empty()) assets<<"static const KwikSound kwik_sounds[1]{};\n";
    else {
        assets<<"static const KwikSound kwik_sounds[] = {\n";
        for(const auto&s:exported_assets.sounds) assets<<"    {\""<<esc(s.name)<<"\",\""<<esc(s.file)<<"\","<<"static_cast<float>("<<number(s.volume)<<"),static_cast<float>("<<number(s.pitch)<<"),"<<s.blob<<"},\n";
        assets<<"};\n";
    }
    assets<<"const KwikSound* g_sound_table=kwik_sounds;\nint g_sound_count="<<exported_assets.sounds.size()<<";\n";
    assets<<"static const KwikTileset kwik_empty_tilesets[1]{};\nconst KwikTileset* g_tilesets=kwik_empty_tilesets;\nint g_tileset_count=0;\n}\n";
    write(out/"generated/assets_registry.cpp",assets.str());
    std::ostringstream maincpp;
    maincpp<<"#include <gml_runtime.h>\n#include \"game_registry.hpp\"\nint main(){ kwik_yyc_generated::kwik_fill_objects(); auto tables=kwik_yyc_generated::make_game_tables(); return gml::run_game(tables); }\n";
    write(out/"generated/main.cpp",maincpp.str());

    std::ostringstream cm;
    cm<<"cmake_minimum_required(VERSION 3.16)\nproject(kwik_yyc_game LANGUAGES C CXX)\nset(CMAKE_CXX_STANDARD 20)\nset(CMAKE_CXX_STANDARD_REQUIRED ON)\n\n";
    cm<<"find_package(Threads REQUIRED)\n";
    cm<<"find_package(OpenGL REQUIRED)\n";
    cm<<"find_package(glfw3 REQUIRED)\n";
    cm<<"find_package(PkgConfig QUIET)\n";
    cm<<"if(PkgConfig_FOUND)\n";
    cm<<"  pkg_check_modules(FFMPEG QUIET libavformat libavcodec libavutil libswscale libswresample)\n";
    cm<<"endif()\n\n";
    cm<<"add_library(kwik_runtime STATIC IMPORTED GLOBAL)\n";
    cm<<"set_target_properties(kwik_runtime PROPERTIES IMPORTED_LOCATION \"${CMAKE_CURRENT_SOURCE_DIR}/libkwik_runtime.a\")\n";
    cm<<"target_include_directories(kwik_runtime INTERFACE \"${CMAKE_CURRENT_SOURCE_DIR}/runtime_include\")\n";
    cm<<"target_link_libraries(kwik_runtime INTERFACE glfw OpenGL::GL ${CMAKE_DL_LIBS} Threads::Threads m)\n";
    cm<<"if(FFMPEG_FOUND)\n";
    cm<<"  target_link_directories(kwik_runtime INTERFACE ${FFMPEG_LIBRARY_DIRS})\n";
    cm<<"  target_link_options(kwik_runtime INTERFACE ${FFMPEG_LDFLAGS_OTHER})\n";
    cm<<"  target_link_libraries(kwik_runtime INTERFACE ${FFMPEG_LIBRARIES})\n";
    cm<<"endif()\n\n";
    cm<<"add_library(yyc_game_code OBJECT generated/yyc_functions.cpp generated/gml_recovered.cpp generated/game_registry.cpp generated/assets_registry.cpp)\n";
    cm<<"target_include_directories(yyc_game_code PUBLIC generated runtime_include)\n";
    cm<<"target_link_libraries(yyc_game_code PUBLIC kwik_runtime)\n";
    cm<<"add_executable(kwik_yyc_game generated/main.cpp $<TARGET_OBJECTS:yyc_game_code>)\n";
    cm<<"target_include_directories(kwik_yyc_game PRIVATE generated runtime_include)\n";
    cm<<"target_link_libraries(kwik_yyc_game PRIVATE kwik_runtime)\n";
    cm<<"add_custom_command(TARGET kwik_yyc_game POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_if_different \"${CMAKE_CURRENT_SOURCE_DIR}/Assets.dat\" \"$<TARGET_FILE_DIR:kwik_yyc_game>/Assets.dat\")\n";
    write(out/"CMakeLists.txt",cm.str());
}
}
