#include <chrono>
#include <iostream>
#include <thread>
#include <unistd.h>
#include <vector>

void print_backtrace();

int bar(int i)
{
  return i + 1;
}

int foo(int i)
{
  return bar(i) + 2;
}

auto long_for(long long loop_cnt) -> int
{
  int fuck_cnt = 0;
  for (int i = 0; i < loop_cnt; i++)
  {
    if (i % 2)
    {
      fuck_cnt += bar(i);
    }
    else
    {
      fuck_cnt += foo(i);
    }
  }
  sleep(1);
  return fuck_cnt;
}

void workload()
{
  // sleep(1);
  asm volatile("" : : : "memory");
  int a = long_for(47483647L);
  asm volatile("" : : : "memory");
  std::cout << a << std::endl;
}

int main(int argc, char **argv)
{
  std::vector<std::thread> threads;

  int thread_num = 100;
  int count = 100;
  while (count--)
  {
    // workload();
    for (int i = 0; i < thread_num; i++)
    {
      threads.emplace_back(std::thread(workload));
    }

    for (int i = 0;i < thread_num; i++)
    {
      if (threads[i].joinable())
        threads[i].join();
    }
    sleep(1);
    threads.clear();
  }

  return 0;
}


