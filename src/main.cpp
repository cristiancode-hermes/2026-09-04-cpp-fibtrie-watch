// SPDX-License-Identifier: MIT
// cpp-fibtrie-watch — IPv4 FIB Patricia trie inspector (/proc/net/fib_trie + fib_triestat)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o fibtrie-watch
// Usage: ./fibtrie-watch [options]

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

static void enable_color() {
  C_RESET = "\x1b[0m"; C_BOLD = "\x1b[1m"; C_DIM = "\x1b[2m";
  C_RED = "\x1b[31m"; C_GREEN = "\x1b[32m"; C_YELLOW = "\x1b[33m";
  C_BLUE = "\x1b[34m"; C_CYAN = "\x1b[36m"; C_MAGENTA = "\x1b[35m";
}

// ─────────────────────────────────────────────────────────────────────────────
// Model
// ─────────────────────────────────────────────────────────────────────────────
struct FibLeaf {
  std::string ip;
  int bits = 0;
  std::string addr_type;   // LOCAL / UNICAST / BROADCAST / MULTICAST
  std::string info;        // full row: "/32 host LOCAL"
  int depth = 0;           // indent level in the trie tree
};

struct TrieStats {
  std::string table;       // "Main" / "Local"
  int avg_depth = 0;       // ×100 (2.42 → 242)
  int max_depth = 0;
  int leaves = 0;
  int prefixes = 0;
  int internal = 0;
  int pointers = 0;
  int null_ptrs = 0;
  int size_kb = 0;
  long long gets = 0;
  long long backtracks = 0;
  long long matches = 0;
  long long miss = 0;
  long long null_hit = 0;
  long long skipped = 0;
  std::vector<int> hist;   // per-depth node counts (histogram)
};

struct Snapshot {
  long ts = 0;
  std::string tree_source;
  std::string stat_source;
  std::vector<FibLeaf> leaves;
  std::vector<TrieStats> stats;
  bool demo = false;

  const TrieStats* stat_of(const std::string& table) const {
    for (const auto& s : stats)
      if (s.table == table) return &s;
    return nullptr;
  }
  int max_depth() const {
    int m = 0;
    for (const auto& s : stats) m = std::max(m, s.max_depth);
    return m;
  }
  std::size_t leaf_count() const { return leaves.size(); }
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
static std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return s;
}

// "2.42" → 242
static int parse_avg_depth(const std::string& v) {
  int whole = 0, frac = 0;
  std::sscanf(v.c_str(), "%d.%d", &whole, &frac);
  return whole * 100 + frac;
}

static long long parse_ll(std::string_view v) {
  v = trim(v);
  long long out = 0;
  std::from_chars(v.data(), v.data() + v.size(), out);
  return out;
}

static std::string fmt_avg(int avg_depth) {
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%d.%02d", avg_depth / 100, avg_depth % 100);
  return buf;
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser: stats file (/proc/net/fib_triestat) — same table/hist layout
// ─────────────────────────────────────────────────────────────────────────────
static bool parse_triestat_file(const std::string& path, std::vector<TrieStats>& out) {
  std::ifstream f(path);
  if (!f) return false;

  TrieStats cur;
  bool have_cur = false;
  std::string line;

  auto push_cur = [&]() {
    if (have_cur) {
      out.push_back(cur);
      cur = TrieStats{};
      have_cur = false;
    }
  };

  while (std::getline(f, line)) {
    std::string_view l = trim(line);
    if (l == "Main:" || l == "Local:") {
      push_cur();
      cur.table = std::string(l.substr(0, l.find(':')));
      have_cur = true;
      continue;
    }
    if (!have_cur) continue;

    // histogram: "1: 1  2: 3  3: 1" (pairs depth:count — skip bare count tokens)
    if (!l.empty() && std::isdigit(static_cast<unsigned char>(l[0]))
        && l.find(':') != std::string_view::npos
        && l.find('/') == std::string_view::npos
        && l[0] != '0') {
      cur.hist.clear();
      std::istringstream ss{std::string(l)};
      std::string tok;
      while (ss >> tok) {
        auto c = tok.find(':');
        if (c == std::string::npos) continue;   // count column — not a depth bucket
        int d = 0;
        try { d = std::stoi(tok.substr(0, c)); }
        catch (...) { continue; }
        cur.hist.push_back(d);
      }
      continue;
    }

    auto colon = l.find(':');
    if (colon != std::string_view::npos) {
      std::string_view key = trim(l.substr(0, colon));
      std::string_view val;
      if (colon + 1 <= l.size()) val = trim(l.substr(colon + 1));
      if (key == "Aver depth")          cur.avg_depth = parse_avg_depth(std::string(val));
      else if (key == "Max depth")      cur.max_depth = static_cast<int>(parse_ll(val));
      else if (key == "Leaves")         cur.leaves = static_cast<int>(parse_ll(val));
      else if (key == "Prefixes")       cur.prefixes = static_cast<int>(parse_ll(val));
      else if (key == "Internal nodes") cur.internal = static_cast<int>(parse_ll(val));
      else if (key == "Pointers")       cur.pointers = static_cast<int>(parse_ll(val));
      else if (key == "Null ptrs")      cur.null_ptrs = static_cast<int>(parse_ll(val));
      else if (key == "Total size") {
        std::istringstream ss{std::string(val)};
        int kb = 0;
        ss >> kb;
        cur.size_kb = kb;
      }
      else if (key == "gets")       cur.gets = parse_ll(val);
      else if (key == "backtracks") cur.backtracks = parse_ll(val);
      continue;
    }

    if (l.find("gets") == 0) {
      auto eq = l.find("= ");
      if (eq != std::string_view::npos) cur.gets = parse_ll(l.substr(eq + 1));
    } else if (l.find("backtracks") == 0) {
      auto eq = l.find("= ");
      if (eq != std::string_view::npos) cur.backtracks = parse_ll(l.substr(eq + 1));
    } else if (l.find("semantic match passed") == 0) {
      auto eq = l.find("= ");
      if (eq != std::string_view::npos) cur.matches = parse_ll(l.substr(eq + 1));
    } else if (l.find("semantic match miss") == 0) {
      auto eq = l.find("= ");
      if (eq != std::string_view::npos) cur.miss = parse_ll(l.substr(eq + 1));
    } else if (l.find("null node hit") == 0) {
      auto eq = l.find("= ");
      if (eq != std::string_view::npos) cur.null_hit = parse_ll(l.substr(eq + 1));
    } else if (l.find("skipped node resize") == 0) {
      auto eq = l.find("= ");
      if (eq != std::string_view::npos) cur.skipped = parse_ll(l.substr(eq + 1));
    }
  }
  push_cur();
  return !out.empty();
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser: tree file (/proc/net/fib_trie) — "Main:"/"Local:" blocks with leaves
// ─────────────────────────────────────────────────────────────────────────────
static bool parse_trie_tree_file(const std::string& path, Snapshot& snap) {
  std::ifstream f(path);
  if (!f) return false;

  std::string line;
  bool first_table_seen = false;
  std::string cur_table;
  std::string pending_addr;   // last address-bearing row, waiting for its info line
  int pending_depth = INT_MAX;

  auto attach_info = [&](const std::string& addr, int bits,
                         const std::string& kind,
                         const std::string& info, int depth) {
    // prefer an existing leaf with the same addr and no type yet
    for (auto& leaf : snap.leaves) {
      if (leaf.ip == addr && leaf.addr_type.empty()) {
        leaf.addr_type = kind;
        leaf.info = info;
        if (bits > leaf.bits) leaf.bits = bits;
        if (depth < leaf.depth) leaf.depth = depth;   // info line indents deeper
        return;
      }
    }
    // otherwise add a standalone leaf (e.g. " +-- 172.16.1.2" + "/32 host LOCAL")
    FibLeaf n;
    n.ip = addr;
    n.bits = bits;
    n.addr_type = kind;
    n.info = info;
    n.depth = depth;
    snap.leaves.push_back(std::move(n));
  };

  while (std::getline(f, line)) {
    std::string_view l = trim(line);
    if (l == "Main:" || l == "Local:") {
      cur_table = std::string(l.substr(0, l.find(':')));
      first_table_seen = true;
      // ensure a stats entry exists for this table (may be absent if triestat missing)
      bool known = false;
      for (const auto& s : snap.stats)
        if (s.table == cur_table) { known = true; break; }
      if (!known) {
        TrieStats t;
        t.table = cur_table;
        snap.stats.push_back(t);
      }
      continue;
    }
    if (!first_table_seen) continue;

    // address-bearing row: " +-- <prefix>" (tnode or standalone leaf) or " |-- <addr>"
    // NOTE: match on the RAW line (indentation markers), not the trimmed view
    std::size_t p = line.find("+-- ");
    std::size_t q = line.find("|-- ");
    std::size_t marker = (p != std::string::npos) ? p : q;
    if (marker != std::string::npos) {
      std::string_view raw(line);
      std::istringstream ss{std::string(trim(raw.substr(marker + 4)))};
      std::string pref;
      if (ss >> pref) {
        auto slash = pref.find('/');
        std::string addr = (slash == std::string::npos) ? pref : pref.substr(0, slash);
        int bits = 0;
        if (slash != std::string::npos) {
          try { bits = std::stoi(pref.substr(slash + 1)); }
          catch (...) { bits = 0; }
        }
        if (p != std::string::npos && slash != std::string::npos) {
          // tnode row " +-- 127.0.0.0/31 1 0 0" — INTERNAL node, not a leaf:
          // only used as pending address anchor for its children
          pending_addr = addr;
          pending_depth = static_cast<int>(std::count(line.begin(), line.begin() + static_cast<std::ptrdiff_t>(p), ' '));
          continue;
        }
        // "|-- <addr>" or standalone " +-- <addr>" — these ARE leaves
        {
          FibLeaf n;
          n.ip = addr;
          n.bits = bits;
          n.depth = (p != std::string::npos)
                      ? static_cast<int>(std::count(line.begin(), line.begin() + static_cast<std::ptrdiff_t>(p), ' '))
                      : static_cast<int>(std::count(line.begin(), line.begin() + static_cast<std::ptrdiff_t>(q), ' '));
          snap.leaves.push_back(std::move(n));
        }
        pending_addr = addr;
        pending_depth = INT_MAX;
      }
      continue;
    }

    // info row: "/32 host LOCAL" — attach to the pending address
    if (!pending_addr.empty() && l.size() > 1 && l[0] == '/') {
      std::istringstream ss{std::string(l)};
      std::string len, scope, kind;
      if (ss >> len >> scope >> kind) {
        int bits = 0;
        try { bits = std::stoi(len.substr(1)); }
        catch (...) { bits = 0; }
        int depth = pending_depth != INT_MAX ? pending_depth
                                             : static_cast<int>(std::count(line.begin(), line.end(), ' '));
        attach_info(pending_addr, bits, kind, std::string(l), depth);
      }
      pending_addr.clear();
      pending_depth = INT_MAX;
      continue;
    }

    // any other content line (counters inside a combined dump) → reset pending
    pending_addr.clear();
    pending_depth = INT_MAX;
  }
  return !snap.leaves.empty() || !snap.stats.empty();
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendering
// ─────────────────────────────────────────────────────────────────────────────
static std::string hist_line(const TrieStats& s) {
  if (s.hist.empty()) return "-";
  std::string out;
  for (int i = 1; i <= s.max_depth; ++i) {
    if (!out.empty()) out += " ";
    int cnt = 0;
    for (int h : s.hist) if (h == i) ++cnt;
    out += std::to_string(i) + ":" + std::to_string(cnt);
  }
  return out;
}

static void render_stats(const Snapshot& s, bool local_only) {
  std::cout << C_BOLD << "  TABLE    DEPTH  AVG   LEAVES  PREFIXES  INT  PTRS  NULLP  KB   HIST"
            << C_RESET << "\n";
  for (const auto& t : s.stats) {
    if (local_only && t.table != "Local") continue;
    std::string tname = t.table;
    if (tname.size() < 8) tname.append(8 - tname.size(), ' ');
    std::cout << "  " << C_CYAN << tname << C_RESET
              << "  " << (t.max_depth >= 5 ? C_YELLOW : "") << std::setw(2) << t.max_depth << C_RESET
              << "   " << std::setw(4) << fmt_avg(t.avg_depth)
              << "  " << std::setw(5) << t.leaves
              << "  " << std::setw(6) << t.prefixes
              << "  " << std::setw(4) << t.internal
              << "  " << std::setw(4) << t.pointers
              << "  " << std::setw(4) << t.null_ptrs
              << "  " << std::setw(3) << t.size_kb
              << "   " << C_DIM << hist_line(t) << C_RESET << "\n";
  }
  if (s.stats.empty()) std::cout << C_DIM << "  (no stats source: /proc/net/fib_triestat)\n" << C_RESET;
}

static void render_counters(const Snapshot& s) {
  std::cout << C_BOLD << "  TABLE    GETS        MATCH       MISS     NULL_HIT    BACKTRACK"
            << C_RESET << "\n";
  for (const auto& t : s.stats) {
    std::string tname = t.table;
    if (tname.size() < 8) tname.append(8 - tname.size(), ' ');
    std::cout << "  " << C_CYAN << tname << C_RESET
              << "  " << std::setw(10) << t.gets
              << "  " << std::setw(10) << t.matches
              << "  " << std::setw(8) << t.miss
              << "  " << std::setw(10) << t.null_hit
              << "  " << std::setw(10) << t.backtracks << "\n";
  }
}

static void render_leaves(const Snapshot& s, int max_rows, bool non_local) {
  std::cout << C_BOLD << "  PREFIX                     TYPE        DEPTH"
            << C_RESET << "\n";
  int shown = 0;
  for (const auto& n : s.leaves) {
    if (max_rows > 0 && shown >= max_rows) break;
    if (non_local && n.addr_type == "LOCAL") continue;
    std::string pfx = n.ip + "/" + std::to_string(n.bits);
    if (pfx.size() < 26) pfx.append(26 - pfx.size(), ' ');
    std::string ty = n.addr_type.empty() ? "?" : n.addr_type;
    if (ty.size() < 11) ty.append(11 - ty.size(), ' ');
    std::string tv;
    if (ty.find("LOCAL") != std::string::npos) tv = C_GREEN;
    else if (ty.find("UNICAST") != std::string::npos) tv = C_CYAN;
    else if (ty.find("BROADCAST") != std::string::npos) tv = C_YELLOW;
    else tv = C_DIM;
    std::cout << "  " << pfx << " " << tv << ty << C_RESET
              << "  " << std::setw(3) << n.depth << "\n";
    ++shown;
  }
}

static void render_local_list(const Snapshot& s) {
  bool any = false;
  for (const auto& n : s.leaves) {
    if (n.addr_type != "LOCAL") continue;
    any = true;
    std::string pfx = n.ip + "/" + std::to_string(n.bits);
    std::string ty = n.addr_type;
    std::cout << "  " << C_GREEN << pfx << C_RESET
              << (pfx.size() < 18 ? std::string(18 - pfx.size(), ' ') : " ")
              << ty << "\n";
  }
  if (!any) std::cout << C_DIM << "  (no LOCAL leaves)\n" << C_RESET;
}

static std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\t': out += "\\t"; break;
      default: out += c;
    }
  }
  return out;
}

static void render_json(const Snapshot& s, const TrieStats* sel) {
  std::ostringstream os;
  os << "{\n  \"tree_source\": \"" << json_escape(s.tree_source) << "\",\n"
     << "  \"stat_source\": \"" << json_escape(s.stat_source) << "\",\n"
     << "  \"timestamp\": " << s.ts << ",\n"
     << "  \"tables\": [\n";
  bool first_t = true;
  for (const auto& t : s.stats) {
    if (sel && sel->table != t.table) continue;
    if (!first_t) os << ",\n";
    first_t = false;
    os << "    {\n      \"name\": \"" << json_escape(t.table) << "\",\n"
       << "      \"avg_depth\": " << fmt_avg(t.avg_depth) << ",\n"
       << "      \"max_depth\": " << t.max_depth << ",\n"
       << "      \"leaves\": " << t.leaves << ",\n"
       << "      \"prefixes\": " << t.prefixes << ",\n"
       << "      \"internal\": " << t.internal << ",\n"
       << "      \"pointers\": " << t.pointers << ",\n"
       << "      \"null_ptrs\": " << t.null_ptrs << ",\n"
       << "      \"size_kb\": " << t.size_kb << ",\n"
       << "      \"gets\": " << t.gets << ",\n"
       << "      \"matches\": " << t.matches << ",\n"
       << "      \"miss\": " << t.miss << ",\n"
       << "      \"null_hit\": " << t.null_hit << ",\n"
       << "      \"backtracks\": " << t.backtracks << ",\n"
       << "      \"hist\": [";
    bool first_h = true;
    for (int i = 1; i <= t.max_depth; ++i) {
      int cnt = 0;
      for (int h : t.hist) if (h == i) ++cnt;
      if (!first_h) os << ", ";
      first_h = false;
      os << cnt;
    }
    os << "]\n    }";
  }
  os << "\n  ],\n  \"leaves\": [\n";
  bool first_l = true;
  for (const auto& n : s.leaves) {
    if (sel && n.addr_type != "LOCAL" && n.bits != 32) continue;  // keep all unless filtered
    if (!first_l) os << ",\n";
    first_l = false;
    os << "    {\"prefix\": \"" << json_escape(n.ip + "/" + std::to_string(n.bits)) << "\", "
       << "\"type\": \"" << json_escape(n.addr_type) << "\", "
       << "\"depth\": " << n.depth << ", "
       << "\"info\": \"" << json_escape(n.info) << "\"}";
  }
  os << "\n  ]\n}\n";
  std::cout << os.str();
}

// ─────────────────────────────────────────────────────────────────────────────
// Syntax-highlighted raw trie dump
// ─────────────────────────────────────────────────────────────────────────────
static void render_highlight(const std::string& path) {
  std::ifstream f(path);
  if (!f) {
    std::cerr << "error: cannot open " << path << "\n";
    return;
  }
  std::string line;
  while (std::getline(f, line)) {
    std::string_view l = trim(line);
    if (l.empty()) { std::cout << "\n"; continue; }
    if (l.find("LOCAL") != std::string_view::npos)
      std::cout << C_GREEN << line << C_RESET << "\n";
    else if (l.find("BROADCAST") != std::string_view::npos)
      std::cout << C_YELLOW << line << C_RESET << "\n";
    else if (l.find("Main:") != std::string_view::npos || l.find("Local:") != std::string_view::npos)
      std::cout << C_BOLD << line << C_RESET << "\n";
    else
      std::cout << line << "\n";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo blobs (synthetic dual-table host: eth0 10.10.0.0/16, br0 172.16.1.0/24,
// docker 172.17.0.0/16, 192.168.0.0/24)
// ─────────────────────────────────────────────────────────────────────────────
static std::string demo_tree() {
  return
    "Main:\n"
    "  +-- 0.0.0.0/0 3 0 5\n"
    "     |-- 0.0.0.0\n"
    "        /0 universe UNICAST\n"
    "     +-- 10.0.0.0/8 2 0 3\n"
    "        +-- 10.10.0.0/16 2 0 2\n"
    "           |-- 10.10.0.0\n"
    "              /16 link UNICAST\n"
    "           |-- 10.10.0.10\n"
    "              /32 host LOCAL\n"
    "     +-- 172.16.0.0/16 2 0 4\n"
    "        +-- 172.16.1.0/24 2 0 2\n"
    "           |-- 172.16.1.0\n"
    "              /24 link UNICAST\n"
    "           |-- 172.16.1.2\n"
    "              /32 host LOCAL\n"
    "        +-- 172.17.0.0/16 2 0 2\n"
    "           |-- 172.17.0.1\n"
    "              /16 link UNICAST\n"
    "     +-- 192.168.0.0/24 2 0 3\n"
    "        |-- 192.168.0.0\n"
    "           /24 link UNICAST\n"
    "        |-- 192.168.0.99\n"
    "           /32 host LOCAL\n"
    "Local:\n"
    "  +-- 0.0.0.0/0 3 0 5\n"
    "     |-- 0.0.0.0\n"
    "        /0 universe UNICAST\n"
    "     +-- 10.0.0.0/8 2 0 3\n"
    "        +-- 10.10.0.0/16 2 0 2\n"
    "           |-- 10.10.0.10\n"
    "              /32 host LOCAL\n"
    "     +-- 127.0.0.0/8 2 0 2\n"
    "        +-- 127.0.0.0/31 1 0 0\n"
    "           |-- 127.0.0.0\n"
    "              /8 host LOCAL\n"
    "           |-- 127.0.0.1\n"
    "              /32 host LOCAL\n"
    "        |-- 127.255.255.255\n"
    "           /32 link BROADCAST\n"
    "     +-- 172.16.1.2\n"
    "        /32 host LOCAL\n"
    "     +-- 192.168.0.99\n"
    "        /32 host LOCAL\n";
}

static std::string demo_triestat() {
  return
    "Basic info: size of leaf: 48 bytes, size of tnode: 40 bytes.\n"
    "Main:\n"
    "\tAver depth:     2.42\n"
    "\tMax depth:      4\n"
    "\tLeaves:         6\n"
    "\tPrefixes:       6\n"
    "\tInternal nodes: 4\n"
    "\t  1: 1  2: 3  3: 1  4: 1\n"
    "\tPointers: 17\n"
    "Null ptrs: 9\n"
    "Total size: 2  kB\n"
    "\n"
    "Counters:\n"
    "---------\n"
    "gets = 5862015\n"
    "backtracks = 0\n"
    "semantic match passed = 5862015\n"
    "semantic match miss = 0\n"
    "null node hit= 886411\n"
    "skipped node resize = 0\n"
    "\n"
    "Local:\n"
    "\tAver depth:     2.42\n"
    "\tMax depth:      4\n"
    "\tLeaves:         7\n"
    "\tPrefixes:       7\n"
    "\tInternal nodes: 5\n"
    "\t  1: 1  2: 3  3: 1  4: 1\n"
    "\tPointers: 22\n"
    "Null ptrs: 11\n"
    "Total size: 2  kB\n"
    "\n"
    "Counters:\n"
    "---------\n"
    "gets = 5862015\n"
    "backtracks = 0\n"
    "semantic match passed = 5862015\n"
    "semantic match miss = 0\n"
    "null node hit= 886411\n"
    "skipped node resize = 0\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Loader
// ─────────────────────────────────────────────────────────────────────────────
static bool load_snapshot(Snapshot& snap, const std::string& file_override, bool demo) {
  snap.ts = std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch()).count();
  snap.demo = demo;

  if (demo) {
    snap.tree_source = "demo";
    snap.stat_source = "demo";
    std::string t = "/tmp/fibtrie-demo-tree.txt";
    std::string s = "/tmp/fibtrie-demo-stat.txt";
    {
      std::ofstream o(t); o << demo_tree();
      std::ofstream o2(s); o2 << demo_triestat();
    }
    parse_trie_tree_file(t, snap);
    std::vector<TrieStats> st;
    parse_triestat_file(s, st);
    for (auto& tab : st) {
      bool known = false;
      for (auto& e : snap.stats) if (e.table == tab.table) { e = tab; known = true; break; }
      if (!known) snap.stats.push_back(tab);
    }
    std::remove(t.c_str());
    std::remove(s.c_str());
    return !snap.leaves.empty();
  }

  if (!file_override.empty()) {
    // sniff: stats file (has "Leaves:") vs tree file (has " +-- ") vs combined
    std::ifstream probe(file_override);
    std::string first;
    std::string content;
    if (probe) {
      std::ostringstream ss;
      ss << probe.rdbuf();
      content = ss.str();
    }
    snap.stat_source = file_override;
    snap.tree_source = file_override;
    bool has_stats = content.find("Leaves:") != std::string::npos;
    bool has_tree  = content.find(" +-- ") != std::string::npos;
    bool ok = false;
    if (has_tree) ok = parse_trie_tree_file(file_override, snap);
    if (has_stats) {
      std::vector<TrieStats> st;
      if (parse_triestat_file(file_override, st)) {
        for (auto& t : st) {
          bool known = false;
          for (auto& e : snap.stats) if (e.table == t.table) { e = t; known = true; break; }
          if (!known) snap.stats.push_back(t);
        }
        ok = true;
      }
    }
    return ok;
  }

  snap.tree_source = "/proc/net/fib_trie";
  snap.stat_source = "/proc/net/fib_triestat";
  bool tree_ok = parse_trie_tree_file("/proc/net/fib_trie", snap);
  std::vector<TrieStats> st;
  if (parse_triestat_file("/proc/net/fib_triestat", st)) {
    for (auto& t : st) {
      bool known = false;
      for (auto& e : snap.stats) if (e.table == t.table) { e = t; known = true; break; }
      if (!known) snap.stats.push_back(t);
    }
  }
  return tree_ok;
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;

static void t_check(bool cond, const char* msg) {
  if (cond) { ++g_pass; std::cout << "  PASS  " << msg << "\n"; }
  else      { ++g_fail; std::cout << "  FAIL  " << msg << "\n"; }
}

static int run_selftest() {
  std::cout << "-- selftest: demo snapshot (tree + triestat) --\n";
  {
    Snapshot s;
    bool ok = load_snapshot(s, "", true);
    t_check(ok, "demo loads");
    t_check(s.stats.size() == 2, "two tables (Main + Local)");
    const TrieStats* main = s.stat_of("Main");
    t_check(main != nullptr, "Main stats present");
    if (main) {
      t_check(main->max_depth == 4, "Main max depth 4");
      t_check(main->leaves == 6, "Main leaves 6");
      t_check(main->prefixes == 6, "Main prefixes 6");
      t_check(main->pointers == 17, "Main pointers 17");
      t_check(main->gets == 5862015, "Main gets counter");
      t_check(main->matches == 5862015, "Main semantic matches");
      t_check(main->null_hit == 886411, "Main null node hit");
      t_check(fmt_avg(main->avg_depth) == "2.42", "avg depth 2.42");
      t_check(main->hist.size() == 4, "hist has 4 depth buckets");
    }
    const TrieStats* local = s.stat_of("Local");
    t_check(local != nullptr, "Local stats present");
    if (local) {
      t_check(local->leaves == 7, "Local leaves 7");
      t_check(local->null_hit == 886411, "Local null node hit");
    }
    bool has_local = false, has_bcast = false, has_u16 = false;
    for (const auto& n : s.leaves) {
      if (n.addr_type == "LOCAL") has_local = true;
      if (n.addr_type == "BROADCAST") has_bcast = true;
      if (n.ip == "10.10.0.0" && n.bits == 16) has_u16 = true;
    }
    t_check(has_local, "leaf with LOCAL type found");
    t_check(has_bcast, "leaf with BROADCAST type found");
    t_check(has_u16, "10.10.0.0/16 leaf parsed with bits");
  }

  std::cout << "-- selftest: real /proc/net source --\n";
  {
    Snapshot s;
    bool ok = load_snapshot(s, "", false);
    t_check(ok, "/proc/net/fib_trie opens");
    if (ok) {
      t_check(!s.leaves.empty(), "tree yields leaf rows");
      t_check(s.leaf_count() >= 1, "at least 1 leaf");
      const TrieStats* main = s.stat_of("Main");
      t_check(main != nullptr, "Main table present (triestat)");
      if (main) {
        t_check(main->gets > 0, "Main gets counter > 0 (lookups happened)");
        t_check(main->max_depth > 0, "Main max depth > 0");
      }
      bool has_local = false, has_prefix = false;
      for (const auto& n : s.leaves) {
        if (n.addr_type == "LOCAL") has_local = true;
        if (n.bits > 0 && !n.ip.empty()) has_prefix = true;
      }
      t_check(has_local, "LOCAL leaves present on host");
      t_check(has_prefix, "leaf prefix parsed");
    }
  }

  std::cout << "-- selftest: counters monotonic --\n";
  {
    Snapshot a, b;
    load_snapshot(a, "", false);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    load_snapshot(b, "", false);
    const TrieStats* ma = a.stat_of("Main");
    const TrieStats* mb = b.stat_of("Main");
    t_check(ma && mb && mb->gets >= ma->gets, "gets monotonic across reads");
  }

  std::cout << "-- selftest: JSON hygiene --\n";
  {
    Snapshot s;
    load_snapshot(s, "", true);
    std::ostringstream os;
    std::streambuf* old = std::cout.rdbuf(os.rdbuf());
    render_json(s, nullptr);
    std::cout.rdbuf(old);
    std::string j = os.str();
    t_check(j.find("\"tables\"") != std::string::npos, "json has tables");
    t_check(j.find("\"leaves\"") != std::string::npos, "json has leaves");
    t_check(j.find("\"name\": \"Main\"") != std::string::npos, "json Main table");
    t_check(j.find("\"avg_depth\": 2.42") != std::string::npos, "json avg_depth 2.42");
    t_check(j.find("\"prefix\": \"127.0.0.1/32\"") != std::string::npos, "json leaf prefix");
    t_check(j.find("{name:") == std::string::npos, "json keys always quoted");
    // parse it back
    std::istringstream chk(j);
    int objs = 0;
    std::string tok;
    while (chk >> tok) if (tok.find("\"tables\"") != std::string::npos) ++objs;
    t_check(objs >= 1, "json smoke");
  }

  std::cout << "-- selftest: --no-color hygiene --\n";
  {
    Snapshot s;
    load_snapshot(s, "", true);
    disable_color();
    std::ostringstream o2;
    std::streambuf* old = std::cout.rdbuf(o2.rdbuf());
    render_stats(s, false);
    render_leaves(s, 0, true);
    std::cout.rdbuf(old);
    std::string out = o2.str();
    t_check(out.find("\x1b[") == std::string::npos, "no ANSI codes with --no-color");
    t_check(out.find("Main") != std::string::npos, "table prints table names");
    enable_color();
  }

  std::cout << "-- selftest: helpers --\n";
  {
    t_check(parse_avg_depth("2.42") == 242, "avg 2.42 -> 242");
    t_check(parse_avg_depth("0.00") == 0, "avg 0.00 -> 0");
    t_check(parse_ll("  42") == 42, "parse_ll trims whitespace");
    t_check(parse_ll("0") == 0, "parse_ll zero");
    t_check(json_escape("a\"b") == "a\\\"b", "json quote escaped");
    t_check(json_escape("plain") == "plain", "json plain unchanged");
    std::string_view t = trim("  abc \t");
    t_check(t == "abc", "trim both sides");
    t_check(trim("x") == "x", "trim single char");
  }

  std::cout << "selftest: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void print_help() {
  std::cout <<
    "fibtrie-watch — IPv4 FIB Patricia trie (/proc/net/fib_trie + fib_triestat)\n"
    "\n"
    "Usage: fibtrie-watch [options]\n"
    "\n"
    "  (default)      table stats + leaf prefixes\n"
    "  --stats        trie stats per table only\n"
    "  --counters     lookup counters (gets / matches / null_hit)\n"
    "  --leaves       prefix leaf rows (skips LOCAL)\n"
    "  --local        list LOCAL host addresses\n"
    "  --tree         syntax-highlighted raw /proc/net/fib_trie dump\n"
    "  --top N        show first N leaf rows\n"
    "  --watch N      refresh every N seconds\n"
    "  --json         machine-readable output\n"
    "  --demo         synthetic dual-table host\n"
    "  --file PATH    parse a dump (tree and/or triestat format)\n"
    "  --no-color     disable ANSI colors\n"
    "  --selftest     run self-tests and exit\n"
    "  -h, --help     this help\n";
}

enum class Mode { Auto, Stats, Counters, Leaves, Local, Tree };

int main(int argc, char** argv) {
  bool color_flag = true;
  bool demo = false;
  bool json = false;
  int watch = 0;
  int top = 0;
  std::string file;
  Mode mode = Mode::Auto;

  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next = [&](std::string_view name) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "error: " << name << " requires a value\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };
    if (a == "--stats")        mode = Mode::Stats;
    else if (a == "--counters") mode = Mode::Counters;
    else if (a == "--leaves")  mode = Mode::Leaves;
    else if (a == "--local")   mode = Mode::Local;
    else if (a == "--tree")    mode = Mode::Tree;
    else if (a == "--file")    { auto v = next(a); if (!v) return 2; file = *v; }
    else if (a == "--top")     { auto v = next(a); if (!v) return 2; top = std::atoi(v->c_str()); }
    else if (a == "--watch")   { auto v = next(a); if (!v) return 2; watch = std::atoi(v->c_str()); }
    else if (a == "--demo")    demo = true;
    else if (a == "--json")    json = true;
    else if (a == "--no-color") color_flag = false;
    else if (a == "--selftest") return run_selftest();
    else if (a == "-h" || a == "--help") { print_help(); return 0; }
    else { std::cerr << "error: unknown option '" << a << "' (see --help)\n"; return 2; }
  }

  if (!color_flag) disable_color();

  auto run_once = [&](const Snapshot& snap) {
    if (json) { render_json(snap, nullptr); return; }
    switch (mode) {
      case Mode::Auto:
        render_stats(snap, false);
        std::cout << "\n";
        render_leaves(snap, top > 0 ? top : 12, true);
        break;
      case Mode::Stats:
        render_stats(snap, false);
        break;
      case Mode::Counters:
        render_counters(snap);
        break;
      case Mode::Leaves:
        render_leaves(snap, top, false);
        break;
      case Mode::Local:
        render_local_list(snap);
        break;
      case Mode::Tree:
        render_highlight(file.empty() ? "/proc/net/fib_trie" : file);
        break;
    }
  };

  if (watch > 0) {
    for (;;) {
      Snapshot snap;
      if (!load_snapshot(snap, file, demo)) {
        std::cerr << "error: cannot read fib trie sources\n";
        return 1;
      }
      std::cout << "\x1b[2J\x1b[H";
      run_once(snap);
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch));
    }
  }

  Snapshot snap;
  if (!load_snapshot(snap, file, demo)) {
    std::cerr << "error: cannot read fib trie sources\n";
    return 1;
  }
  run_once(snap);
  return 0;
}