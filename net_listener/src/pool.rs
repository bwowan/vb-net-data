use std::cell::UnsafeCell;
use std::mem::MaybeUninit;

struct PoolState<const COUNT: usize> {
    slots_free_count: usize,
    slots_free: [u16; COUNT],
    slots_ref_counts: [u8; COUNT],
}

struct MemPool<T, const COUNT: usize> {
    slots_bodies: [UnsafeCell<MaybeUninit<T>>; COUNT],
    state: spin::Mutex<PoolState<COUNT>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Handle(usize);

unsafe impl<T: Send, const COUNT: usize> Send for MemPool<T, COUNT> {}
unsafe impl<T: Send, const COUNT: usize> Sync for MemPool<T, COUNT> {}

impl<T, const COUNT: usize> MemPool<T, COUNT> {
    fn new() -> Self {
        // Убеждаемся, что COUNT помещается в u16,
        // но оставляем запас, чтобы (i as u16) + 1 не вызвало переполнение для u16::MAX
        const { assert!(COUNT <= u16::MAX as usize); }

        Self {
            slots_bodies: std::array::from_fn(|_| UnsafeCell::new(MaybeUninit::uninit())),
            state: spin::Mutex::new(PoolState {
                slots_free_count: COUNT,
                slots_free: std::array::from_fn(|i| (i as u16) + 1), // [1, 2, 3, ..., COUNT]
                slots_ref_counts: std::array::from_fn(|_| 0),
            }),
        }
    }

    fn allocate(&self) -> Option<(Handle, *mut T)> {
        let mut state = self.state.lock();
        if state.slots_free_count == 0 {
            return None;
        }
        state.slots_free_count -= 1;
        let handle = Handle(state.slots_free[state.slots_free_count] as usize);
        let idx: usize = handle.0 as usize - 1;
        state.slots_ref_counts[idx] = 1;
        drop(state);
        let ptr = unsafe { (*self.slots_bodies[idx].get()).as_mut_ptr() };
        Some((handle, ptr))
    }

    fn get(&self, handle: Handle) -> Option<&T> {
        let idx: usize = handle.0 as usize - 1;
        if idx < COUNT {
            let mut state = self.state.lock();
            assert!(state.slots_ref_counts[idx] < u8::MAX, "refcount overflow");
            state.slots_ref_counts[idx] += 1;
            drop(state);
            Some(unsafe { &*(*self.slots_bodies[idx].get()).as_ptr() })
        } else {
            None
        }
    }

    fn deallocate(&self, handle: Handle) {
        let idx: usize = handle.0 as usize - 1;
        if idx < COUNT {
            let mut state = self.state.lock();
            if state.slots_ref_counts[idx] > 1 {
                state.slots_ref_counts[idx] -= 1;
            } else {
                state.slots_ref_counts[idx] = 0;
                let free_idx = state.slots_free_count;
                state.slots_free[free_idx] = handle.0 as u16;
                state.slots_free_count += 1;
            }
        }
    }

    fn deallocate_but_pinned(&self, handle: Handle) {
        let idx: usize = handle.0 as usize - 1;
        let mut state = self.state.lock();
        if state.slots_ref_counts[idx] > 0 {
            state.slots_ref_counts[idx] -= 1;
        }
    }
}
