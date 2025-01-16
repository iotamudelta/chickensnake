use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::vec::Vec;
use std::{mem, ptr};

#[repr(C)]
pub struct State {
    initialized: bool,
    process: py_spy::PythonSpy,
}

#[no_mangle]
pub extern "C" fn chickensnake_init(pid: i32) -> *mut State {
    //let state = State { process: None };

    //let result = std::panic::catch_unwind(|| {
    let mut config = py_spy::Config::default();
    config.blocking = py_spy::config::LockingStrategy::AlreadyLocked;
    config.native = true;
    let proc = py_spy::PythonSpy::new(pid, &config);

    let state = State {
        initialized: true,
        process: proc.expect("Failed to create py_spy proc"),
    };
    //});
    //if result.is_err() {
    //    eprintln!("error: rust panicked");
    //}

    Box::into_raw(Box::new(state))
}

#[no_mangle]
pub unsafe extern "C" fn chickensnake_traces(
    state: *mut State,
    outlen: *mut c_int,
) -> *mut *mut std::os::raw::c_char {
    let mut stacks = vec![];
    if (*state).initialized {
        let traces = (*state)
            .process
            .get_stack_traces()
            .expect("Failed to get traces of process.");

        for trace in traces {
            let header = format!("Thread {:#X} ({})", trace.thread_id, trace.status_str());
            stacks.push(CString::new(header).unwrap());
            for frame in &trace.frames {
                let fra = format!("\t {} ({}:{})", frame.name, frame.filename, frame.line);
                stacks.push(CString::new(fra).unwrap())
            }
        }
    }

    let mut stack_pointers: Vec<_> = stacks.into_iter().map(|s| s.into_raw()).collect();
    stack_pointers.shrink_to_fit();

    let len = stack_pointers.len();
    let ptr = stack_pointers.as_mut_ptr();
    std::mem::forget(stack_pointers);

    ptr::write(outlen, len as c_int);
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn chickensnake_free_traces(ptr: *mut *mut c_char, len: c_int) {
    let len = len as usize;
    let v = Vec::from_raw_parts(ptr, len, len);
    for elem in v {
        let s = CString::from_raw(elem);
        mem::drop(s);
    }
}
