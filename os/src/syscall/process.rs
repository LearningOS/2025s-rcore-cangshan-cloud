//! Process management syscalls
use crate::{
    config::{
        PAGE_SIZE,
        MAX_SYSCALL_NUM,
    },
    mm::{
        translated_byte_buffer, 
        MapPermission,
        VirtAddr,
        VPNRange,
    }, 
    task::{
        create_new_map_area,
        get_current_task_page_table, 
        remove_map_area,
    }, 
    timer::get_time_us
};

use crate::task:: {
    current_user_token,
    get_syscall_counter,
    exit_current_and_run_next,
    suspend_current_and_run_next,
    change_program_brk
};

use core::mem::size_of;
#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let buffers = translated_byte_buffer(current_user_token(), ts as *const u8, size_of::<TimeVal>());
    let ref time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let src_ptr = time_val as *const TimeVal;
    for (idx, buffer) in buffers.into_iter().enumerate() {
        let unit_len = buffer.len();
        unsafe {
            buffer.copy_from_slice(core::slice::from_raw_parts(
                src_ptr.wrapping_byte_add(idx * unit_len) as *const u8,
                unit_len)
            );
        }
    }
    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");

    match trace_request {
        // 功能0，读取当前任务 id 地址处一个字节的无符号整数值
        0 => {
            // 检查用户空间可读性
            let token = current_user_token();
            let buffers = translated_byte_buffer(token, id as *const u8, 1);
            if buffers.is_empty() {
                return -1;
            }
            // 只读第一个字节
            buffers[0][0] as isize
        },

        // 功能1，写入 data 到该用户程序 id 地址处
        1 => {
            let token = current_user_token();
            let mut buffers = translated_byte_buffer(token, id as *mut u8, 1);
            if buffers.is_empty() {
                return -1;
            }
            buffers[0][0] = data as u8;
            0
        },

        // 功能2，查询当前系统调用次数，本次调用也计入统计
        2 =>  {
            if id < MAX_SYSCALL_NUM {
                get_syscall_counter(id) as isize
            } else {
                -1
            }
        },

        _ => -1,
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    trace!("kernel: sys_mmap");

    // 参数合法性检查
    if start % PAGE_SIZE != 0 ||
        len % PAGE_SIZE!= 0 ||
        len == 0 ||
        prot & !0x7 != 0 ||
        prot & 0x7 ==0 ||
        (prot & 0x1 == 0 && prot & 0x2 != 0) ||
        start >= 0x80000000  ||
        start + len > 0x80000000 ||
        start + len < start {
            return -1;
        }
    
    // 检查区间是否已被完整映射
    let start_vpn = VirtAddr::from(start).floor();
    let end_vpn = VirtAddr::from(start + len).ceil();
    let vpns = VPNRange::new(start_vpn, end_vpn);
    for vpn in vpns {
        if let Some(pte) = get_current_task_page_table(vpn) {
            if pte.is_valid() {
                return -1;
            }
        }
    }
    // 创建新映射区域
    create_new_map_area(
        VirtAddr::from(start),
        VirtAddr::from(start + len),
        MapPermission::from_bits_truncate((prot << 1) as u8) | MapPermission::U
    );
    0
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");

    // 参数合法性检查
    if start >= 0x80000000 ||
        start % PAGE_SIZE != 0 {
            return -1;
        }
    let mut mlen = len;
    if start > 0x80000000 - len {
        mlen = 0x80000000 - start;
    }
    remove_map_area(start, mlen)
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
