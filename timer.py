import time

class Timer:
  def __init__(self):
    self.pause_time = None
    self.elapsed_time = None
    self.start_time = None
    self.is_stopped = True
    self.is_paused = False
  
  def pause(self):
    if not self.is_paused:
      self.elapsed_time = time.perf_counter() - self.start_time
      self.is_paused = True

  def stop(self):
    if not self.is_paused:
      self.elapsed_time = time.perf_counter() - self.start_time
    self.is_stopped = True
    self.is_paused = False

  def start(self):
    if self.is_stopped:
      self.start_time = time.perf_counter()
      self.is_stopped = False
    elif self.is_paused:
      self.start_time = time.perf_counter() - self.elapsed_time
      self.is_paused = False

  def is_running(self):
    return not (self.is_paused or self.is_stopped)

  def time(self):
    if self.is_stopped or self.is_paused:
      return self.elapsed_time
    else:
      return time.perf_counter() - self.start_time
