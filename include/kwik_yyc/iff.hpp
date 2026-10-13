#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
namespace kwik::yyc {
struct IffChunk { std::string tag; uint64_t offset{}; uint32_t size{}; };
struct IffResource { std::string kind; uint32_t index{}; std::string name; };
struct IffObject { std::string name; int32_t sprite_index{-1}; int32_t parent_index{-100}; int32_t persistent{}; int32_t visible{1}; int32_t solid{}; int32_t depth{}; int32_t mask_index{-1}; };
struct IffRoomInstance { int32_t x{},y{},object_index{-1},id{}; double scale_x{1},scale_y{1}; int32_t image_index{}; double angle{}; int32_t depth{}; int32_t creation_code{-1},precreate_code{-1}; };
struct IffRoomLayer { std::string name; int32_t id{},type{},depth{},x{},y{},visible{1},sprite{-1},htiled{},vtiled{},stretch{}; uint32_t color{0xffffffffu}; int32_t tile_first{},tile_count{},tileset{-1},grid_w{},grid_h{}; };
struct IffRoom { std::string name; int32_t width{},height{}; uint32_t bg_color{}; int32_t speed{30},persistent{},creation_code{-1},view_x{},view_y{},view_w{},view_h{},view_border_x{32},view_border_y{32},view_speed_x{-1},view_speed_y{-1},view_object{-1}; std::vector<IffRoomInstance> instances; std::vector<IffRoomLayer> layers; };
struct IffInfo { uint32_t form_size{}; std::string game_name; int32_t window_width{}, window_height{}, game_fps{60}, start_room{}; std::vector<IffChunk> chunks; std::vector<IffResource> resources; std::vector<IffObject> objects; std::vector<IffRoom> rooms; bool has(std::string_view tag) const; std::string resource_name(std::string_view kind,uint32_t index) const; };
IffInfo parse_game_data(const std::filesystem::path& path);
}
