#ifndef SIGNAL_INFO
#define SIGNAL_INFO
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

class SignalInfo
{
public:
  
  void getSignalInfo(pid_t pid,pid_t tid) const
  {
    std::string procPath = "/proc/"+std::to_string(pid)+"/task/"+std::to_string(tid)+"/status";
    std::ifstream procFile(procPath);
    if(!procFile.is_open()){
        return;
    }
    std::string line;
    while(std::getline(procFile,line)){
        if(line.find("SigQ")!=std::string::npos ||
        line.find("SigBlk")!=std::string::npos)
        DEBUG(line.c_str());
    }
  }

}


#endif
