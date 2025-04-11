//! Process management syscalls
use crate::{
    config::MAX_SYSCALL_NUM, task::{exit_current_and_run_next, suspend_current_and_run_next}, timer::get_time_us
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// get time with second and microsecond
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    unsafe {
        *ts = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
    }
    0
}

// TODO: implement the syscall
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    let current_task = crate::task::get_current_task();

    match trace_request {
        // 功能0，读取当前任务 id 地址处一个字节的无符号整数值
        0 => {
            unsafe  {
                *(id as *const u8) as isize
            }
        },
        
        // 功能1，写入_data到该用户程序_id地址处
        1 => {
            unsafe {
                *(id as *mut u8) = data as u8;
            }
            0
        },

        // 功能2，查询当前系统调用次数，本次调用也计入统计
        2 =>  {
            if id < MAX_SYSCALL_NUM {
                crate::task::get_syscall_counter(current_task, id) as isize
            } else {
                -1
            }
        },

        _ => -1,
    }
}
