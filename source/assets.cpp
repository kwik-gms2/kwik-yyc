#include "kwik_yyc/assets.hpp"
#include <bzlib.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <map>
#include <stdexcept>
#include <unordered_map>

namespace kwik::yyc {
namespace {

struct Chunk { size_t off{}; uint32_t size{}; };
struct RawImage { int w{}, h{}; std::vector<uint8_t> rgba; };
struct PageItem {
    int sx{}, sy{}, sw{}, sh{}, tx{}, ty{}, tw{}, th{}, bw{}, bh{}, page{};
};

uint16_t u16(const std::vector<uint8_t>& d,size_t o){if(o+2>d.size())throw std::runtime_error("truncated asset data");return uint16_t(d[o])|uint16_t(d[o+1])<<8;}
int16_t i16(const std::vector<uint8_t>& d,size_t o){return static_cast<int16_t>(u16(d,o));}
uint32_t u32(const std::vector<uint8_t>& d,size_t o){if(o+4>d.size())throw std::runtime_error("truncated asset data");uint32_t v;std::memcpy(&v,d.data()+o,4);return v;}
int32_t i32(const std::vector<uint8_t>& d,size_t o){return static_cast<int32_t>(u32(d,o));}
float f32(const std::vector<uint8_t>& d,size_t o){uint32_t v=u32(d,o);float f;std::memcpy(&f,&v,4);return f;}
bool inside(const std::vector<uint8_t>&d,size_t o,size_t n=1){return o<=d.size()&&n<=d.size()-o;}
std::string str(const std::vector<uint8_t>&d,uint32_t o){if(o>=d.size())return {};size_t e=o;while(e<d.size()&&d[e])++e;if(e==d.size())return {};return std::string(reinterpret_cast<const char*>(d.data()+o),e-o);}

std::vector<uint8_t> read_file(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("could not open asset source: "+p.string());return {std::istreambuf_iterator<char>(f),{}};}

std::map<std::string,Chunk> chunks(const std::vector<uint8_t>&d){
    if(d.size()<8||std::memcmp(d.data(),"FORM",4)!=0)throw std::runtime_error("asset source is not a GameMaker FORM file");
    std::map<std::string,Chunk> out;
    for(size_t p=8;p+8<=d.size();){std::string t(reinterpret_cast<const char*>(d.data()+p),4);uint32_t s=u32(d,p+4);if(p+8ull+s>d.size())throw std::runtime_error("bad IFF chunk");out[t]={p,s};p+=8ull+s;}
    return out;
}

int sx(int v,int bits){const int m=1<<(bits-1);return (v^m)-m;}

RawImage decode_fioq(const std::vector<uint8_t>&q){
    if(q.size()<12||std::memcmp(q.data(),"fioq",4)!=0)throw std::runtime_error("invalid fioq texture");
    int w=int(u16(q,4)),h=int(u16(q,6));uint32_t n=u32(q,8);if(12ull+n>q.size()||w<=0||h<=0)throw std::runtime_error("invalid fioq dimensions");
    RawImage out;out.w=w;out.h=h;out.rgba.resize(size_t(w)*h*4);
    std::array<std::array<uint8_t,4>,64> index{};
    size_t p=12;int run=0;int r=0,g=0,b=0,a=255;
    for(size_t o=0;o<out.rgba.size();o+=4){
        if(run>0)--run;
        else if(p<12ull+n){
            int b1=q[p++];
            if((b1&0xc0)==0x00){auto c=index[size_t(b1&63)];r=c[0];g=c[1];b=c[2];a=c[3];}
            else if((b1&0xe0)==0x40)run=b1&0x1f;
            else if((b1&0xe0)==0x60){if(p>=q.size())throw std::runtime_error("truncated fioq run");run=(((b1&0x1f)<<8)|q[p++])+32;}
            else if((b1&0xc0)==0x80){r=(r+sx((b1>>4)&3,2))&255;g=(g+sx((b1>>2)&3,2))&255;b=(b+sx(b1&3,2))&255;}
            else if((b1&0xe0)==0xc0){if(p>=q.size())throw std::runtime_error("truncated fioq diff16");int b2=q[p++];r=(r+sx(b1&0x1f,5))&255;g=(g+sx((b2>>4)&0xf,4))&255;b=(b+sx(b2&0xf,4))&255;}
            else if((b1&0xf0)==0xe0){if(p+1>=q.size())throw std::runtime_error("truncated fioq diff24");int b2=q[p++],b3=q[p++];int dr=((b1&0xf)<<1)|((b2>>7)&1);int dg=(b2>>2)&0x1f;int db=((b2&3)<<3)|((b3>>5)&7);int da=b3&0x1f;r=(r+sx(dr,5))&255;g=(g+sx(dg,5))&255;b=(b+sx(db,5))&255;a=(a+sx(da,5))&255;}
            else if((b1&0xf0)==0xf0){if(b1&8){if(p>=q.size())throw std::runtime_error("truncated fioq color");r=q[p++];}if(b1&4){if(p>=q.size())throw std::runtime_error("truncated fioq color");g=q[p++];}if(b1&2){if(p>=q.size())throw std::runtime_error("truncated fioq color");b=q[p++];}if(b1&1){if(p>=q.size())throw std::runtime_error("truncated fioq color");a=q[p++];}}
            auto& c=index[size_t((r^g^b^a)&63)];c={uint8_t(r),uint8_t(g),uint8_t(b),uint8_t(a)};
        }
        out.rgba[o]=uint8_t(r);out.rgba[o+1]=uint8_t(g);out.rgba[o+2]=uint8_t(b);out.rgba[o+3]=uint8_t(a);
    }
    return out;
}

RawImage decode_texture(const std::vector<uint8_t>&d,size_t p,size_t end){
    if(!inside(d,p,12))throw std::runtime_error("bad texture payload");
    if(std::memcmp(d.data()+p,"fioq",4)==0){uint32_t n=u32(d,p+8);if(!inside(d,p,12ull+n))throw std::runtime_error("truncated fioq");return decode_fioq(std::vector<uint8_t>(d.begin()+p,d.begin()+p+12ull+n));}
    if(std::memcmp(d.data()+p,"2zoq",4)==0){
        uint32_t want=u32(d,p+8);std::vector<uint8_t> q(want);unsigned int dst=want;unsigned int src=unsigned(std::min(end,d.size())-(p+12));int rc=BZ2_bzBuffToBuffDecompress(reinterpret_cast<char*>(q.data()),&dst,reinterpret_cast<char*>(const_cast<uint8_t*>(d.data()+p+12)),src,0,0);if(rc!=BZ_OK)throw std::runtime_error("BZip2 texture decompression failed: "+std::to_string(rc));q.resize(dst);return decode_fioq(q);
    }
    throw std::runtime_error("unsupported embedded GameMaker texture format");
}

uint32_t crc32_bytes(const uint8_t* p,size_t n){uint32_t c=0xffffffffu;for(size_t i=0;i<n;++i){c^=p[i];for(int k=0;k<8;++k)c=(c>>1)^((0u-(c&1u))&0xedb88320u);}return c^0xffffffffu;}
uint32_t adler32_bytes(const std::vector<uint8_t>&v){uint32_t a=1,b=0;for(uint8_t x:v){a=(a+x)%65521u;b=(b+a)%65521u;}return (b<<16)|a;}
void be32(std::vector<uint8_t>&o,uint32_t v){o.push_back(uint8_t(v>>24));o.push_back(uint8_t(v>>16));o.push_back(uint8_t(v>>8));o.push_back(uint8_t(v));}
void chunk_png(std::vector<uint8_t>&o,const char t[4],const std::vector<uint8_t>&v){size_t s=o.size();be32(o,uint32_t(v.size()));o.insert(o.end(),t,t+4);o.insert(o.end(),v.begin(),v.end());uint32_t c=crc32_bytes(o.data()+s+4,4+v.size());be32(o,c);}

std::vector<uint8_t> png_rgba(const RawImage&im){
    std::vector<uint8_t> o={137,80,78,71,13,10,26,10};std::vector<uint8_t> ih;be32(ih,uint32_t(im.w));be32(ih,uint32_t(im.h));ih.insert(ih.end(),{8,6,0,0,0});chunk_png(o,"IHDR",ih);
    std::vector<uint8_t> raw;raw.reserve(size_t(im.h)*(1+size_t(im.w)*4));for(int y=0;y<im.h;++y){raw.push_back(0);size_t b=size_t(y)*im.w*4;raw.insert(raw.end(),im.rgba.begin()+b,im.rgba.begin()+b+size_t(im.w)*4);}
    std::vector<uint8_t> z={0x78,0x01};size_t p=0;while(p<raw.size()){size_t n=std::min<size_t>(65535,raw.size()-p);bool final=p+n==raw.size();z.push_back(final?1:0);uint16_t nn=uint16_t(n),inv=uint16_t(~nn);z.push_back(uint8_t(nn));z.push_back(uint8_t(nn>>8));z.push_back(uint8_t(inv));z.push_back(uint8_t(inv>>8));z.insert(z.end(),raw.begin()+p,raw.begin()+p+n);p+=n;}be32(z,adler32_bytes(raw));chunk_png(o,"IDAT",z);chunk_png(o,"IEND",{});return o;
}

RawImage page_item_image(const RawImage&page,const PageItem&t){
    RawImage o;o.w=t.bw;o.h=t.bh;if(o.w<=0||o.h<=0)throw std::runtime_error("invalid TPAG bounding box");o.rgba.assign(size_t(o.w)*o.h*4,0);
    if(t.sw<=0||t.sh<=0||t.tw<=0||t.th<=0)return o;
    for(int y=0;y<t.th;++y)for(int x=0;x<t.tw;++x){int sxp=t.sx+(x*t.sw)/t.tw,syp=t.sy+(y*t.sh)/t.th,dx=t.tx+x,dy=t.ty+y;if(sxp<0||syp<0||sxp>=page.w||syp>=page.h||dx<0||dy<0||dx>=o.w||dy>=o.h)continue;size_t si=(size_t(syp)*page.w+sxp)*4,di=(size_t(dy)*o.w+dx)*4;std::memcpy(o.rgba.data()+di,page.rgba.data()+si,4);}
    return o;
}

PageItem page_item(const std::vector<uint8_t>&d,size_t p){if(!inside(d,p,22))throw std::runtime_error("bad TPAG item");return {int(u16(d,p)),int(u16(d,p+2)),int(u16(d,p+4)),int(u16(d,p+6)),int(u16(d,p+8)),int(u16(d,p+10)),int(u16(d,p+12)),int(u16(d,p+14)),int(u16(d,p+16)),int(u16(d,p+18)),int(i16(d,p+20))};}

void le32(std::vector<uint8_t>&o,uint32_t v){o.push_back(uint8_t(v));o.push_back(uint8_t(v>>8));o.push_back(uint8_t(v>>16));o.push_back(uint8_t(v>>24));}

}

ExportedAssets extract_game_assets(const std::filesystem::path& path){
    auto d=read_file(path);auto cs=chunks(d);ExportedAssets out;
    auto get=[&](const char*t)->const Chunk*{auto it=cs.find(t);return it==cs.end()?nullptr:&it->second;};
    std::vector<RawImage> pages;
    if(auto*c=get("TXTR")){size_t b=c->off+8;uint32_t n=u32(d,b);std::vector<size_t> ptrs;ptrs.reserve(n);for(uint32_t i=0;i<n;++i){size_t p=u32(d,b+4+4ull*i);size_t q=0;for(size_t off=4;off<=32;off+=4){if(!inside(d,p+off,4))continue;size_t z=u32(d,p+off);if(z<d.size()&&inside(d,z,4)&&(std::memcmp(d.data()+z,"2zoq",4)==0||std::memcmp(d.data()+z,"fioq",4)==0)){q=z;break;}}if(!q)throw std::runtime_error("could not locate TXTR payload "+std::to_string(i));ptrs.push_back(q);}for(size_t i=0;i<ptrs.size();++i){size_t end=c->off+8ull+c->size;for(size_t q:ptrs)if(q>ptrs[i]&&q<end)end=q;pages.push_back(decode_texture(d,ptrs[i],end));}}
    if(auto*c=get("SPRT")){size_t b=c->off+8;uint32_t n=u32(d,b);out.sprites.resize(n);for(uint32_t i=0;i<n;++i){size_t p=u32(d,b+4+4ull*i);ExportedSprite s;s.name=str(d,u32(d,p));s.width=i32(d,p+4);s.height=i32(d,p+8);s.bbox_left=i32(d,p+12);s.bbox_right=i32(d,p+16);s.bbox_bottom=i32(d,p+20);s.bbox_top=i32(d,p+24);s.origin_x=i32(d,p+48);s.origin_y=i32(d,p+52);s.speed_type=i32(d,p+64);s.speed=f32(d,p+68);s.sep_masks=i32(d,p+44);uint32_t fc=u32(d,p+84);s.first_frame=int(out.images.size());s.frame_count=int(fc);for(uint32_t k=0;k<fc;++k){size_t tp=u32(d,p+88+4ull*k);PageItem t=page_item(d,tp);if(t.page<0||t.page>=int(pages.size()))throw std::runtime_error("sprite TPAG page out of range");auto im=page_item_image(pages[size_t(t.page)],t);out.images.push_back({im.w,im.h,png_rgba(im)});}size_t mp=p+88+4ull*fc;if(s.sep_masks==1&&inside(d,mp,4)){uint32_t mc=u32(d,mp);size_t row=(size_t(std::max(0,s.width))+7)/8,one=row*size_t(std::max(0,s.height));if(mc>0&&mc<10000&&inside(d,mp+4,one*mc)){ExportedBlob mb;mb.type=4;le32(mb.bytes,mc);le32(mb.bytes,uint32_t(s.width));le32(mb.bytes,uint32_t(s.height));mb.bytes.insert(mb.bytes.end(),d.begin()+mp+4,d.begin()+mp+4+one*mc);s.mask_blob=int(out.blobs.size());out.blobs.push_back(std::move(mb));}}out.sprites[i]=std::move(s);}}
    if(auto*c=get("FONT")){size_t b=c->off+8;uint32_t n=u32(d,b);out.fonts.resize(n);for(uint32_t i=0;i<n;++i){size_t p=u32(d,b+4+4ull*i);ExportedFont f;f.name=str(d,u32(d,p));uint32_t em=u32(d,p+8);float ef;std::memcpy(&ef,&em,4);f.size=(em&0x80000000u)?int(std::lround(-ef)):int(em);size_t tp=u32(d,p+28);if(tp){PageItem t=page_item(d,tp);if(t.page>=0&&t.page<int(pages.size())){auto im=page_item_image(pages[size_t(t.page)],t);f.atlas_image=int(out.images.size());out.images.push_back({im.w,im.h,png_rgba(im)});}}size_t list=p+56;uint32_t gc=u32(d,list);f.glyph_start=int(out.glyphs.size());f.glyph_count=int(gc);for(uint32_t g=0;g<gc;++g){size_t gp=u32(d,list+4+4ull*g);if(!inside(d,gp,14))continue;out.glyphs.push_back({int(u16(d,gp)),int(u16(d,gp+2)),int(u16(d,gp+4)),int(u16(d,gp+6)),int(u16(d,gp+8)),int(i16(d,gp+10)),int(i16(d,gp+12))});}f.glyph_count=int(out.glyphs.size())-f.glyph_start;out.fonts[i]=std::move(f);}}
    std::vector<std::vector<uint8_t>> audio;
    if(auto*c=get("AUDO")){size_t b=c->off+8;uint32_t n=u32(d,b);audio.resize(n);for(uint32_t i=0;i<n;++i){size_t p=u32(d,b+4+4ull*i);uint32_t sz=u32(d,p);if(inside(d,p+4,sz))audio[i]=std::vector<uint8_t>(d.begin()+p+4,d.begin()+p+4+sz);}}
    if(auto*c=get("SOND")){size_t b=c->off+8;uint32_t n=u32(d,b);out.sounds.resize(n);for(uint32_t i=0;i<n;++i){size_t p=u32(d,b+4+4ull*i);ExportedSound s;s.name=str(d,u32(d,p));s.file=str(d,u32(d,p+12));s.volume=f32(d,p+20);s.pitch=f32(d,p+24);int aid=i32(d,p+32);if(aid>=0&&aid<int(audio.size())&&!audio[size_t(aid)].empty()){s.blob=int(out.blobs.size());out.blobs.push_back({0,std::move(audio[size_t(aid)])});}out.sounds[i]=std::move(s);}}
    return out;
}

void write_assets_dat(const std::filesystem::path& path,const ExportedAssets& a){
    size_t header=size_t(a.images.size())*2+4*(a.images.size()+a.blobs.size());std::vector<uint8_t> out(header,0);std::vector<uint32_t> offsets;offsets.reserve(a.images.size()+a.blobs.size());
    for(const auto&im:a.images){offsets.push_back(uint32_t(out.size()));le32(out,uint32_t(im.width));le32(out,uint32_t(im.height));le32(out,0);le32(out,uint32_t(im.png.size()));out.insert(out.end(),im.png.begin(),im.png.end());}
    for(const auto&b:a.blobs){offsets.push_back(uint32_t(out.size()));le32(out,uint32_t(b.type));le32(out,uint32_t(b.bytes.size()));out.insert(out.end(),b.bytes.begin(),b.bytes.end());}
    size_t table=a.images.size()*2;for(size_t i=0;i<offsets.size();++i){uint32_t v=offsets[i];out[table+i*4]=uint8_t(v);out[table+i*4+1]=uint8_t(v>>8);out[table+i*4+2]=uint8_t(v>>16);out[table+i*4+3]=uint8_t(v>>24);}
    std::filesystem::create_directories(path.parent_path());std::ofstream f(path,std::ios::binary);if(!f)throw std::runtime_error("could not write "+path.string());f.write(reinterpret_cast<const char*>(out.data()),std::streamsize(out.size()));
}

}
