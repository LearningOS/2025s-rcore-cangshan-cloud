//! Process management syscalls
use crate::{
    mm::{
        MapPermission, 
        VirtAddr, 
        VPNRange,
        MapType,
        MemorySet,
    },
    task::{
        change_program_brk, 
        current_task, 
        current_user_token, 
        exit_current_and_run_next, 
        suspend_current_and_run_next
    },
    timer::get_time_ms,
    config::PAGE_SIZE,
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
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    get_time_ms() as isize
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    let current_task = get_current_task();
    let token = current_user_token();

    match trace_request {
        // 功能0，读取当前任务 id 地址处一个字节的无符号整数值
        0 => {
            // 尝试读取用户空间的内存
            let buffers = translated_byte_buffer(token, id as *const u8, 1);
            if buffers.is_empty() {
                return -1;
            }
            
            // 检查页表项是否有读权限
            let page_table = PageTable::from_token(token);
            let va = VirtAddr::from(id);
            let vpn = va.floor();
            match page_table.translate(vpn) {
                Some(pte) => {
                    if !pte.is_valid() || !pte.readable() {
                        return -1;
                    }
                    buffers[0][0] as isize
                }
                _ => -1,
            }
        },
        
        // 功能1，写入data到该用户程序id地址处
        1 => {
            // 检查页表项是否有写权限
            let page_table = PageTable::from_token(token);
            let va = VirtAddr::from(id);
            let vpn = va.floor();
            match page_table.translate(vpn) {
                Some(pte) => {
                    if !pte.is_valid() || !pte.writable() {
                        return -1;
                    }
                    
                    // 尝试写入用户空间的内存
                    let buffers = translated_byte_buffer(token, id as *const u8, 1);
                    if buffers.is_empty() {
                        return -1;
                    }
                    
                    // 写入数据
                    buffers[0][0] = data as u8;
                    0
                }
                _ => -1,
            }
        },

        // 功能2，查询当前系统调用次数，本次调用也计入统计
        2 =>  {
            if id < MAX_SYSCALL_NUM {
                get_syscall_counter(current_task, id) as isize
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
    
    // 检查参数合法性
    if start % PAGE_SIZE != 0 || prot & !0x7 != 0 || prot & 0x7 == 0 {
        return -1;
    }
    
    // 计算需要映射的长度（按页向上取整）
    let len = if len == 0 { 0 } else { (len - 1) / PAGE_SIZE + 1 } * PAGE_SIZE;
    
    // 获取当前任务
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    
    // 检查要映射的区域是否已经被映射
    let start_vpn = VirtAddr(start).floor();
    let end_vpn = VirtAddr(start + len).ceil();
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        if inner.memory_set.translate(vpn).is_some() {
            return -1;
        }
    }
    
    // 设置映射权限
    let mut map_perm = MapPermission::U;
    if (prot & 0x1) != 0 { map_perm |= MapPermission::R; }
    if (prot & 0x2) != 0 { map_perm |= MapPermission::W; }
    if (prot & 0x4) != 0 { map_perm |= MapPermission::X; }
    
    // 创建新的映射区域
    inner.memory_set.insert_framed_area(
        VirtAddr(start),
        VirtAddr(start + len),
        map_perm
    );
    0
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    
    // 检查参数合法性
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    
    // 计算需要取消映射的长度（按页向上取整）
    let len = if len == 0 { 0 } else { (len - 1) / PAGE_SIZE + 1 } * PAGE_SIZE;
    
    // 获取当前任务
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    
    // 检查要取消映射的区域是否已经被映射
    let start_vpn = VirtAddr(start).floor();
    let end_vpn = VirtAddr(start + len).ceil();
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        if inner.memory_set.translate(vpn).is_none() {
            return -1;
        }
    }
    
    // 取消映射
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
