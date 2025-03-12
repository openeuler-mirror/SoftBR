#ifndef EXECUTABLE_SEGMENTS
#define EXECUTABLE_SEGMENTS
#include "utils.h"
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

class ExecutableSegments
{
public:
  ExecutableSegments(bool exclude_shared_lib)
  {
    INFO("ExecutableSegments");
    parseProcMaps(exclude_shared_lib);
  }
  ///
  bool in_profiler(uintptr_t address){
    ERROR("address in profiler ?");
    return address >= segment_profiler.first && address < segment_profiler.second;
   }


  bool isAddressInExecutableSegment(uintptr_t address) const
  {
    auto it = segment_map.upper_bound(address);
    if (it == segment_map.begin())
      return false;
    --it;
    return address >= it->first && address < it->second;
  }

 int getExecutableSegmentSize(uint64_t pc) const
 { 
    auto it = segment_map.upper_bound(pc);
    if (it == segment_map.begin())
      return 0;
    --it;
    if(pc >= it->first && pc < it->second)
      return it->second - pc;
    return 0;
 }

private:
  std::map<uintptr_t, uintptr_t> segment_map;
  std::pair<uintptr_t, uintptr_t> segment_profiler;
  bool shouldSkipLibrary(const std::string& libName){
    return libName.find("linux-vdso") != std::string::npos ||
           libName.find("libpthread") != std::string::npos ||
           libName.find("libdynamorio") != std::string::npos ||
           libName.find("libunwind") != std::string::npos ||
           libName.find("libstdc++") != std::string::npos ||
           libName.find("libgcc_s") != std::string::npos ||
           libName.find("libm") != std::string::npos ||
           libName.find("libc") != std::string::npos||
           libName.find("ld-linux-aarch64") != std::string::npos ||
           libName.find("profiler") != std::string::npos;

   }
   bool is_profiler(const std::string& libName){
    return libName.find("profiler") != std::string::npos;
   }
   
  void parseProcMaps(bool exclude_shared_lib)
  {
    std::ifstream mapsFile("/proc/self/maps");
    if (!mapsFile.is_open())
    {
      perror("open");
      return;
    }

    std::string line;
    char permissions[5]; // e.g., "r-xp"
    char path[256] = {0};
    while (std::getline(mapsFile, line))
    {
      uintptr_t seg_start, seg_end;
      std::string permissions, offset, dev, inode, pathname;

      std::istringstream lineStream(line);
      lineStream >> std::hex >> seg_start;
      lineStream.ignore(1, '-');
      lineStream >> std::hex >> seg_end;
      lineStream >> permissions >> offset >> dev >> inode;

      if (permissions.find('x') == std::string::npos)
      {
        continue;
      }

      if (!(lineStream >> pathname) || (exclude_shared_lib && pathname.find(".so") != std::string::npos))
      {
        INFO("(%#lx-%#lx) %s is skipped", seg_start, seg_end, pathname.c_str());
        // continue;
        if (is_profiler(pathname)) {
          segment_profiler.first = seg_start;
          segment_profiler.second = seg_end;
          INFO("profiler executable segment: %#lx-%#lx %s", seg_start, seg_end, pathname.c_str());
          continue;
        }
        if(shouldSkipLibrary(pathname)){
          continue;
        }
      }
        
      segment_map[seg_start] = seg_end;
      INFO("new executable segment: %#lx-%#lx %s", seg_start, seg_end, pathname.c_str());
    }
  }
};
#endif