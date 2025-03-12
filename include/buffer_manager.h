#ifndef BUFFER_MANAGER
#define BUFFER_MANAGER
#include "log.h"
#include "stack_lbr_utils.h"
#include <condition_variable>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#include <atomic>
#include <map>
#include "dr_api.h"
#include "dr_tools.h"
class BufferManager
{
public:
    BufferManager(int num_threads, const std::string &output_path) : num_threads_(num_threads), stop_writer_(false)
    {
       

        output_file.open(output_path);
        if (!output_file.is_open())
        {
            ERROR("fail to init the output file");
        }
    }

    ~BufferManager()
    {
        return;
    }

    void malloc_all_buffers()
    {
        std::unique_lock<std::mutex> lock(clean_mutex_);
        for (int i = 0; i < num_threads_ * 2; ++i)
        {
            clean_buffers_.push(std::make_shared<StackLBRBuffer>());
        }
        clean_buffer_cv_.notify_all();
    }

    void delete_all_buffers()
    {
        std::unique_lock<std::mutex> dirty_lock(dirty_mutex_);
        if (dirty_buffers_.size() > 0)
        {
            INFO("there are %d dirty buffers to flush", dirty_buffers_.size());
            while (!dirty_buffers_.empty())
            {
                auto buffer = dirty_buffers_.front();
                clean_buffers_.push(buffer);
                dirty_buffers_.pop();
                buffer->output(output_file);
            }
        }
        dirty_lock.unlock();
        std::unique_lock<std::mutex> clean_lock(clean_mutex_);
        while (!clean_buffers_.empty())
        {
            auto buffer = clean_buffers_.front();
            clean_buffers_.pop();
        }
    }

    std::shared_ptr<StackLBRBuffer> get_clean_buffer()
    {
        std::unique_lock<std::mutex> lock(clean_mutex_);

        while (clean_buffers_.empty())
        {
            clean_buffer_cv_.wait(lock);
        }

        std::shared_ptr<StackLBRBuffer> buffer = clean_buffers_.front();
        clean_buffers_.pop();

        return buffer;
    }

    void return_dirty_buffer(std::shared_ptr<StackLBRBuffer> buffer) 
    {
        std::unique_lock<std::mutex> lock(dirty_mutex_); 

        dirty_buffers_.push(buffer);
        lock.unlock();
        dirty_buffer_cv_.notify_all();
    }

    std::shared_ptr<StackLBRBuffer> swap_buffer(std::shared_ptr<StackLBRBuffer> dirty_buffer) 
    {
        return_dirty_buffer(dirty_buffer);

        return get_clean_buffer();
    }

    void start_writer_thread()
    {
        stop_writer_ = false;
        writer_thread_ = std::thread([this]()
                                     { write_dirty_buffers(); });
    }

    void stop_writer_thread()
    {
        INFO("try to terminiate the writer thread");
        {
            
            stop_writer_ = true;
        }
        dirty_buffer_cv_.notify_all();

        if (writer_thread_.joinable())
        {
            writer_thread_.join();
        }
    }

private:
    void write_dirty_buffers()
    {
        while (true)
        {
            std::unique_lock<std::mutex> dirty_lock(dirty_mutex_);

            dirty_buffer_cv_.wait(dirty_lock, [this]() { return !dirty_buffers_.empty() || stop_writer_; });

            if (stop_writer_)
            {
                break;
            }

            std::shared_ptr<StackLBRBuffer> buffer = dirty_buffers_.front();
            dirty_buffers_.pop();
            dirty_lock.unlock();

            INFO("writer begin to write a new buffer");
            buffer->output(output_file);
            buffer->reset();
             std::unique_lock<std::mutex> clean_lock(clean_mutex_);
            clean_buffers_.push(buffer);
            clean_buffer_cv_.notify_all();
        }

        INFO("writer thread is over");
    }

    int num_threads_;
    std::queue<std::shared_ptr<StackLBRBuffer>> clean_buffers_;
    std::queue<std::shared_ptr<StackLBRBuffer>> dirty_buffers_;
    std::mutex mutex_;
    //TODO mutex is not signal asynchronous safe, consider using lock-free queue
    std::mutex clean_mutex_;
    std::mutex dirty_mutex_;
    std::condition_variable clean_buffer_cv_;
    std::condition_variable dirty_buffer_cv_;

    std::thread writer_thread_;
    bool stop_writer_;
public:
    std::map<pid_t, std::shared_ptr<StackLBRBuffer>> bufferMap;
    std::vector<pid_t> tidsVector;
    std::ofstream output_file;
};

#endif // BUFFER_MANAGER_H

