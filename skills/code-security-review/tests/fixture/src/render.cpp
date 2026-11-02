// C++: the memory rules run over it as they run over C, spelled through std::.
#include <cstdlib>
#include <cstring>
#include <string>

struct Frame { char data[64]; };

void fill(Frame *f, const char *src, size_t n)          // EXPECT-FUNC: fill
{
    std::memcpy(f->data, src, n);                       // EXPECT: MEM-002
}

char *dup_name(const std::string &s)                    // EXPECT-FUNC: dup_name
{
    char *out = new char[s.size()];                     // EXPECT: MEM-010
    std::strcpy(out, s.c_str());                        // EXPECT: MEM-001
    return out;
}

void drop(Frame *f)                                     // EXPECT-FUNC: drop
{
    delete f;                                           // EXPECT: MEM-008
    f->data[0] = 0;
}

int run_tool(const std::string &arg)                    // EXPECT-FUNC: run_tool
{
    return std::system(("tool " + arg).c_str());        // EXPECT: INJ-002
}

// Appended below so that nothing citing the lines above moves.
struct Header { unsigned len; };

unsigned header_len(const unsigned char *data)          // EXPECT-FUNC: header_len
{
    auto *h = reinterpret_cast<const Header *>(data);   // EXPECT: LOG-006
    return h->len;
}

// Appended below so that nothing citing the lines above moves. Two methods
// with one name in one file: stage 1 gives each its own MEM-WFS, told apart by
// the ordinal in function_key (load::0 and load::1), and the candidate gate
// has to count two functions there, not one pair recorded twice.
struct Reader {
    int load(const std::string &path)                   // EXPECT-FUNC: load
    {
        return std::system(("cat " + path).c_str());    // EXPECT: INJ-002
    }
};

struct Writer {
    int load(const std::string &path)                   // EXPECT-FUNC: load
    {
        return std::system(("touch " + path).c_str());  // EXPECT: INJ-002
    }
};
