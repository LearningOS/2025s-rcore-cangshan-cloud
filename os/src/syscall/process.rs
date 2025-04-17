//! Process management syscalls
use crate::{
    mm::{
        MapPermission, 
        VirtAddr, 
        VPNRange,
        address::VPNRange,
        MemorySet::MapType,
        PageTable,
        translated_byte_buffer,
    },
    task::{
        change_program_brk, 
        current_task, 
        current_user_token, 
        exit_current_and_run_next, 
        suspend_current_and_run_next
    },
    timer::get_time_ms,
    config::{
        PAGE_SIZE,
        MAX_SYSCALL_NUM,
    }
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
    -1
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    -1
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
    let task = current_task();
    let mut inner = task.inner_exclusive_access();
    let start_vpn = VirtAddr(start).floor();
    let end_vpn = VirtAddr(start + len).ceil();
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        if inner.memory_set.translate(vpn).is_some() {
            return -1;
        }
    }

    // 4. 权限转换
    let mut map_perm = MapPermission::U;
    if (prot & 0x1) != 0 { map_perm |= MapPermission::R; }
    if (prot & 0x2) != 0 { map_perm |= MapPermission::W; }
    if (prot & 0x4) != 0 { map_perm |= MapPermission::X; }

    // 5. 匿名映射
    inner.memory_set.insert_framed_area(
        VirtAddr(start),
        VirtAddr(start + len),
        map_perm
    );
    0
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");

    // 1. 参数合法性检查
    if start % PAGE_SIZE != 0 {
        return -1;
    }

    // 2. 计算长度
    let len = if len == 0 { 0 } else { ((len - 1) / PAGE_SIZE + 1) * PAGE_SIZE };

    // 3. 检查区间是否已被完整映射
    let task = current_task();
    let mut inner = task.inner_exclusive_access();
    let start_vpn = VirtAddr(start).floor();
    let end_vpn = VirtAddr(start + len).ceil();
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        if inner.memory_set.translate(vpn).is_none() {
            return -1;
        }
    }

    // 4. 只允许完整、唯一的区间取消映射
    inner.memory_set.remove_area_with_start_vpn(start_vpn);
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
