#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace kwik::yyc {

struct ExportedImage {
    int width{};
    int height{};
    std::vector<uint8_t> png;
};

struct ExportedSprite {
    std::string name;
    int first_frame{};
    int frame_count{};
    int origin_x{};
    int origin_y{};
    double speed{};
    int speed_type{};
    int bbox_left{};
    int bbox_top{};
    int bbox_right{};
    int bbox_bottom{};
    int width{};
    int height{};
    int sep_masks{};
    int mask_blob{-1};
};

struct ExportedGlyph {
    int ch{};
    int x{};
    int y{};
    int w{};
    int h{};
    int shift{};
    int offset{};
};

struct ExportedFont {
    std::string name;
    int atlas_image{-1};
    int glyph_start{};
    int glyph_count{};
    int size{};
};

struct ExportedBlob {
    int type{};
    std::vector<uint8_t> bytes;
};

struct ExportedSound {
    std::string name;
    std::string file;
    float volume{1.0f};
    float pitch{1.0f};
    int blob{-1};
};

struct ExportedAssets {
    std::vector<ExportedImage> images;
    std::vector<ExportedSprite> sprites;
    std::vector<ExportedFont> fonts;
    std::vector<ExportedGlyph> glyphs;
    std::vector<ExportedSound> sounds;
    std::vector<ExportedBlob> blobs;
};

ExportedAssets extract_game_assets(const std::filesystem::path& path);
void write_assets_dat(const std::filesystem::path& path, const ExportedAssets& assets);

}
