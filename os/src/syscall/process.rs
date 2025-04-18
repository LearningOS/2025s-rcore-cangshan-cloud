//! Process management syscalls
use crate::{
    config::{
        MAX_SYSCALL_NUM, PAGE_SIZE
    }, mm::{
        address::VPNRange, translated_byte_buffer, MapPermission, MemorySet, PageTable, VPNRange, VirtAddr
    }, 
    timer::{get_time_ms, get_time_us}
};

use crate::task:: {
    exit_current_and_run_next,suspend_current_and_run_next,get_current_task,get_syscall_counter,change_program_brk,TASK_MANAGER
};
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
    let buffers =
        translated_byte_buffer((current_user_token()), ts as *const u8, size_of::<TimeVal>());
    let us = get_time_us();
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let mut time_var_ptr = &time_val as *const _ as *const u8;
    for buffer in buffers {
        unsafe {
            time_var_ptr.copy_to(buffer.as_mut_ptr(), buffer.len());
            time_var_ptr = time_var_ptr.add(buffer.len());
        }
    }
    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    let current_task = get_current_task();

    match trace_request {
        0 => {
            unsafe {
                *(id as *const u8) as isize
            }
        },

        1 => {
            unsafe {
                *(id as *const u8) = data as u8;
            }
            0
        },

        2=> {
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

    // 1. 参数合法性检查
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    if prot & !0x7 != 0 {
        return -1;
    }
    if prot & 0x7 == 0 {
        return -1;
    }

    // 2. 计算映射长度（按页向上取整）
    let len = if len == 0 { 0 } else { ((len - 1) / PAGE_SIZE + 1) * PAGE_SIZE };

    // 3. 检查区间是否已被映射
    let task = get_current_task();
    let mut inner = TASK_MANAGER.inner.exclusive_access();
    let task_control_block = &inner.tasks[task];
    let mut memory_set = &task_control_block.memory_set;
    if memory_set.check_overlap(
        VirtAddr::from(start), 
        VirtAddr::from(start + len)
    ) {
        return -1;
    }

    // 4. 权限转换
    let mut permission = MapPermission::from_bits((prot as u8) << 1).unwrap();
    permission.set(MapPermission::U, true);

    // 5. 匿名映射
    memory_set.insert_framed_area (
        VirtAddr::from(start),
        VirtAddr::from(start + len),
        permission,
    );
    0
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");

    // 1. 参数合法性检查
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    if prot & !0x7 != 0 {
        return -1;
    }
    if prot & 0x7 == 0 {
        return -1;
    }

    // 2. 计算长度
    let len = if len == 0 { 0 } else { ((len - 1) / PAGE_SIZE + 1) * PAGE_SIZE };

    // 3. 检查区间是否已被完整映射
    let task = get_current_task();
    let mut inner = TASK_MANAGER.inner.exclusive_access();
    let task_control_block = &inner.tasks[task];
    let mut memory_set = &task_control_block.memory_set;

    if !memory_set.check_overlap(
        VirtAddr::from(start), 
        VirtAddr::from(start + len)
    ) {
        return -1;
    }
    // 4. 只允许完整、唯一的区间取消映射
    memory_set.remove_area_with_start_vpn(
        VirtAddr::from(start).floor()
    );
    0
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
