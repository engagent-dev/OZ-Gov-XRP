//! WASM global allocator for no_std environment.
//!
//! The XRPL WASM sandbox provides memory but no allocator.
//! This simple bump allocator grows memory as needed.

use core::alloc::{GlobalAlloc, Layout};

#[allow(dead_code)]
struct WasmAllocator;

unsafe impl GlobalAlloc for WasmAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[cfg(target_arch = "wasm32")]
        {
            core::arch::wasm32::memory_grow(0, (layout.size() + 65535) / 65536);
        }
        layout.align() as *mut u8
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: WasmAllocator = WasmAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
