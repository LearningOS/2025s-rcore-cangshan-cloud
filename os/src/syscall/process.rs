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
    let token = current_user_token();
    let ptr = ts as usize;
    let len = core::mem::size_of::<TimeVal>();
    let buffers = translated_byte_buffer(token, ptr as *const u8, len);

    // 检查所有缓冲区是否可写
    if buffers.is_empty() {
        return -1;
    }
    let page_table = PageTable::from_token(token);
    let mut check_addr = ptr;
    let end_addr = ptr + len;
    while check_addr < end_addr {
        let vpn = VirtAddr::from(check_addr).floor();
        if let Some(pte) = page_table.translate(vpn) {
            if !pte.is_valid() || !pte.writable() || !pte.user() {
                return -1;
            }
        } else {
            return -1;
        }
        check_addr = (vpn.0 + 1) * PAGE_SIZE;
    }

    // 获取时间
    let ms = get_time_ms();
    let sec = ms / 1000;
    let usec = (ms % 1000) * 1000;
    let timeval = TimeVal { sec, usec };

    // 写入用户空间
    let timeval_bytes = unsafe {
        core::slice::from_raw_parts(
            &timeval as *const TimeVal as *const u8,
            core::mem::size_of::<TimeVal>(),
        )
    };
    let mut copied = 0;
    for buf in buffers {
        let len = buf.len().min(timeval_bytes.len() - copied);
        buf[..len].copy_from_slice(&timeval_bytes[copied..copied + len]);
        copied += len;
        if copied >= timeval_bytes.len() {
            break;
        }
    }
    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    let va = VirtAddr::from(id);
    let vpn = va.floor();

    match trace_request {
        // 读取
        0 => {
            // 检查权限
            if let Some(pte) = page_table.translate(vpn) {
                if !pte.is_valid() || !pte.readable() || !pte.user() {
                    return -1;
                }
            } else {
                return -1;
            }
            let buffers = translated_byte_buffer(token, id as *const u8, 1);
            if buffers.is_empty() {
                return -1;
            }
            buffers[0][0] as isize
        }
        // 写入
        1 => {
            if let Some(pte) = page_table.translate(vpn) {
                if !pte.is_valid() || !pte.writable() || !pte.user() {
                    return -1;
                }
            } else {
                return -1;
            }
            let buffers = translated_byte_buffer(token, id as *const u8, 1);
            if buffers.is_empty() {
                return -1;
            }
            buffers[0][0] = data as u8;
            0
        }
        // 查询系统调用次数
        2 => {
            if id < MAX_SYSCALL_NUM {
                get_syscall_counter(current_task(), id) as isize
            } else {
                -1
            }
        }
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
