#pragma once
#include "kwik_yyc/elf.hpp"
#include "kwik_yyc/iff.hpp"
#include "kwik_yyc/yyc.hpp"
#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

namespace kwik::yyc {
struct VariableSlot {
    std::string name;
    uint64_t name_va{};
    uint64_t id_va{};
    uint32_t initial_id{};
};

struct Instruction {
    uint64_t address{};
    std::string mnemonic;
    std::string operands;
    std::string text;
    uint64_t referenced_va{};
    bool has_referenced_va{};
    uint64_t branch_target{};
    bool has_branch_target{};
};

struct BasicBlock {
    uint64_t start{};
    uint64_t end{};
    std::vector<uint64_t> successors;
};

struct VariableUse {
    uint64_t instruction_va{};
    uint64_t id_va{};
    std::string name;
};

enum class VariableScope { Unknown, Self, Other, Global };

struct ScopedVariableUse {
    uint64_t instruction_va{};
    uint64_t accessor_call_va{};
    uint64_t id_va{};
    std::string name;
    VariableScope scope{VariableScope::Unknown};
    bool write{};
};

struct VariableCopyAssignment {
    uint64_t instruction_va{};
    std::string target;
    VariableScope target_scope{VariableScope::Unknown};
    std::string source;
    VariableScope source_scope{VariableScope::Unknown};
    uint64_t owner_block{};
};

struct ConstantAssignment {
    uint64_t instruction_va{};
    std::string variable;
    double value{};
    VariableScope scope{VariableScope::Unknown};
    uint64_t owner_block{};
};

struct BooleanAssignment {
    uint64_t instruction_va{};
    std::string variable;
    bool value{};
    VariableScope scope{VariableScope::Unknown};
    uint64_t owner_block{};
};

struct RecoveredArgument {
    std::string expression;
    std::string kind;
    VariableScope scope{VariableScope::Unknown};
    uint64_t value_slot{};
    uint32_t raw_type{0xffffffffu};
    uint64_t raw_payload{};
    std::string callee;
    std::vector<RecoveredArgument> children;
};

struct NamedCall {
    uint64_t instruction_va{};
    uint64_t target{};
    std::string name;
    int argc{-1};
    std::vector<RecoveredArgument> arguments;
    uint64_t owner_block{};
};

struct BuiltinCall {
    uint64_t instruction_va{};
    uint64_t target{};
    std::string name;
    int declared_arity{};
    uint32_t flags{};
    int argc{-1};
    std::vector<RecoveredArgument> arguments;
    uint64_t owner_block{};
};

struct BuiltinResultAssignment {
    uint64_t instruction_va{};
    std::string target;
    VariableScope target_scope{VariableScope::Unknown};
    std::string builtin;
    int argc{-1};
    std::vector<RecoveredArgument> arguments;
    uint64_t owner_block{};
};

struct VariableValueAssignment {
    uint64_t instruction_va{};
    std::string target;
    VariableScope target_scope{VariableScope::Unknown};
    RecoveredArgument value;
    uint64_t owner_block{};
};

struct DynamicInstanceAssignment {
    uint64_t instruction_va{};
    RecoveredArgument target;
    std::string variable;
    RecoveredArgument value;
    uint64_t owner_block{};
};

struct DynamicValueCall {
    uint64_t instruction_va{};
    RecoveredArgument callable;
    std::vector<RecoveredArgument> arguments;
    uint64_t owner_block{};
};

struct TargetUserEventCall {
    uint64_t instruction_va{};
    RecoveredArgument target;
    int user_event{};
    uint64_t owner_block{};
};

struct CompoundAssignment {
    uint64_t instruction_va{};
    std::string target;
    VariableScope target_scope{VariableScope::Unknown};
    std::string op;
    std::string source;
    VariableScope source_scope{VariableScope::Unknown};
    bool has_immediate{};
    double immediate{};
    uint64_t owner_block{};
};

struct RelationalBranch {
    uint64_t compare_call_va{};
    uint64_t branch_va{};
    uint64_t true_target{};
    uint64_t false_target{};
    std::string variable;
    VariableScope scope{VariableScope::Unknown};
    std::string op;
    double value{};
};

struct EqualityBranch {
    uint64_t compare_call_va{};
    uint64_t branch_va{};
    uint64_t true_target{};
    uint64_t false_target{};
    std::string variable;
    VariableScope scope{VariableScope::Unknown};
    double value{};
};

struct SwitchCase {
    double value{};
    uint64_t target{};
};

struct RecoveredSwitch {
    std::string variable;
    VariableScope scope{VariableScope::Unknown};
    uint64_t dispatch_va{};
    uint64_t default_target{};
    std::vector<SwitchCase> cases;
};

struct TruthyBranch {
    uint64_t variable_read_va{};
    uint64_t branch_va{};
    uint64_t true_target{};
    uint64_t false_target{};
    std::string variable;
    VariableScope scope{VariableScope::Unknown};
};

struct BuiltinTruthyBranch {
    uint64_t call_va{};
    uint64_t branch_va{};
    uint64_t true_target{};
    uint64_t false_target{};
    std::string builtin;
    int argc{-1};
    std::vector<RecoveredArgument> arguments;
};

struct ExpressionBranch {
    uint64_t compare_call_va{};
    uint64_t branch_va{};
    uint64_t true_target{};
    uint64_t false_target{};
    RecoveredArgument lhs;
    std::string op;
    RecoveredArgument rhs;
};

struct StructuredIfRegion {
    uint64_t branch_va{};
    uint64_t true_entry{};
    uint64_t false_entry{};
    uint64_t join{};
    std::vector<uint64_t> true_blocks;
    std::vector<uint64_t> false_blocks;
};

struct StructuredSwitchCaseRegion {
    double value{};
    uint64_t entry{};
    std::vector<uint64_t> blocks;
};

struct StructuredSwitchRegion {
    std::string variable;
    VariableScope scope{VariableScope::Unknown};
    uint64_t dispatch_va{};
    uint64_t join{};
    uint64_t default_entry{};
    std::vector<uint64_t> default_blocks;
    std::vector<StructuredSwitchCaseRegion> cases;
};

struct StructuredLoopRegion {
    uint64_t header{};
    uint64_t latch{};
    uint64_t branch_va{};
    uint64_t body_entry{};
    uint64_t exit{};
    bool condition_true_enters{true};
    std::vector<uint64_t> blocks;
    std::vector<uint64_t> break_blocks;
    std::vector<uint64_t> continue_blocks;
};

struct ShortCircuitRegion {
    uint64_t first_branch_va{};
    uint64_t second_branch_va{};
    std::string op;
    uint64_t true_entry{};
    uint64_t false_entry{};
    uint64_t join{};
};

struct LocalValueAssignment {
    uint64_t instruction_va{};
    uint64_t stack_slot{};
    std::string name;
    RecoveredArgument value;
    uint64_t owner_block{};
};

struct ReturnValueWrite {
    uint64_t instruction_va{};
    RecoveredArgument value;
    uint64_t owner_block{};
};

struct BuiltinSymbol {
    std::string name;
    uint64_t function_va{};
    int declared_arity{};
    uint32_t flags{};
};

struct FunctionAnalysis {
    std::string name;
    uint64_t start{};
    uint64_t end{};
    std::vector<Instruction> instructions;
    std::vector<BasicBlock> blocks;
    std::vector<uint64_t> direct_calls;
    std::vector<VariableUse> variable_uses;
    std::vector<ScopedVariableUse> scoped_variable_uses;
    std::vector<VariableCopyAssignment> variable_copies;
    std::vector<ConstantAssignment> constant_assignments;
    std::vector<BooleanAssignment> boolean_assignments;
    std::vector<NamedCall> named_calls;
    std::vector<BuiltinCall> builtin_calls;
    std::vector<BuiltinResultAssignment> builtin_result_assignments;
    std::vector<VariableValueAssignment> variable_value_assignments;
    std::vector<DynamicInstanceAssignment> dynamic_instance_assignments;
    std::vector<DynamicValueCall> dynamic_value_calls;
    std::vector<TargetUserEventCall> target_user_events;
    std::vector<CompoundAssignment> compound_assignments;
    std::vector<RelationalBranch> relational_branches;
    std::vector<RecoveredSwitch> switches;
    std::vector<TruthyBranch> truthy_branches;
    std::vector<BuiltinTruthyBranch> builtin_truthy_branches;
    std::vector<ExpressionBranch> expression_branches;
    std::vector<EqualityBranch> equality_branches;
    std::vector<StructuredIfRegion> structured_ifs;
    std::vector<StructuredSwitchRegion> structured_switches;
    std::vector<StructuredLoopRegion> structured_loops;
    std::vector<ShortCircuitRegion> short_circuits;
    std::vector<LocalValueAssignment> local_assignments;
    std::vector<ReturnValueWrite> return_values;
};

struct CodeAnalysis {
    std::vector<VariableSlot> variables;
    std::vector<BuiltinSymbol> builtins;
    std::vector<FunctionAnalysis> functions;
};

std::vector<VariableSlot> discover_variable_slots(const ElfImage& elf);
std::vector<BuiltinSymbol> discover_builtin_symbols(const ElfImage& elf);
std::unordered_map<uint64_t, uint64_t> recover_fde_starts(const ElfImage& elf);
CodeAnalysis analyze_code(const std::filesystem::path& executable, const ElfImage& elf, const IffInfo& iff, const Discovery& discovery);
}
