#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

template<typename T>
class SynchronizedQueue
{
  std::queue<T> queue_;
  std::mutex mutex_;
  std::condition_variable condvar_;
  bool shutdown_ = false;

  typedef std::lock_guard<std::mutex> lock;
  typedef std::unique_lock<std::mutex> ulock;

public:
  void push(T const& val)
  {
    lock l(mutex_); // prevents multiple pushes corrupting queue_
    bool wake = queue_.empty(); // we may need to wake consumer
    queue_.push(val);
    if (wake)
      condvar_.notify_one();
  }

  // Blocks until an element is available or shutdown() has been called.
  // Returns the element, or std::nullopt if the queue was shut down while empty.
  std::optional<T> pop()
  {
    ulock u(mutex_);
    condvar_.wait(u, [this] { return !queue_.empty() || shutdown_; });
    if (shutdown_)
      return std::nullopt;
    T retval = queue_.front();
    queue_.pop();
    return retval;
  }

  // Unblocks any thread waiting in pop() so it can observe the shutdown flag.
  void shutdown()
  {
    lock l(mutex_);
    shutdown_ = true;
    condvar_.notify_all();
  }

  const bool empty()
  {
    lock l(mutex_);
    return queue_.empty();
  }
};
