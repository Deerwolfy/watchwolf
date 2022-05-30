"""Provides a general timer class"""
import time


class Timer:
    """Wall clock timer"""
    def __init__(self):
        self.pause_time = None
        self.elapsed_time = None
        self.start_time = None
        self.is_stopped = True
        self.is_paused = False

    def pause(self):
        """Pause timer"""
        if not self.is_paused:
            self.elapsed_time = time.perf_counter() - self.start_time
            self.is_paused = True

    def stop(self):
        """Reset and stop timer"""
        if not self.is_paused:
            self.elapsed_time = time.perf_counter() - self.start_time
        self.is_stopped = True
        self.is_paused = False

    def start(self):
        """Start or unpause timer"""
        if self.is_stopped:
            self.start_time = time.perf_counter()
            self.is_stopped = False
        elif self.is_paused:
            self.start_time = time.perf_counter() - self.elapsed_time
            self.is_paused = False

    def is_running(self):
        """Return bool value indicating timer status"""
        return not (self.is_paused or self.is_stopped)

    def time(self):
        """Return elapsed time"""
        if self.is_stopped or self.is_paused:
            return self.elapsed_time
        return time.perf_counter() - self.start_time
