use std::cell::UnsafeCell;
use std::mem::MaybeUninit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle(pub usize);

pub struct PoolSlot<T: Send + Clone> {
    pub handle: Handle,
    pub body: *mut T,
}

impl<T: Send + Clone> PoolSlot<T> {
    fn new(handle: Handle, body: *mut T) -> Self {
        Self { handle, body }
    }
}

unsafe impl<T: Send + Clone> Send for PoolSlot<T> {}
unsafe impl<T: Send + Clone> Sync for PoolSlot<T> {}

struct PoolState<const COUNT: usize> {
    slots_free_count: usize,
    slots_free: [u16; COUNT],
    slots_ref_counts: [u8; COUNT],
}

/// `T: Clone` — слот хранит значение на месте; копия, если нужна, делается явно.
/// В отличие от `Copy`, допускается `Drop` (`Vec`/`String`/`NetData`).
pub struct MemPool<T: Send + Clone, const COUNT: usize> {
    state : spin::Mutex<PoolState<COUNT>>,
    bodies: Box<[UnsafeCell<MaybeUninit<T>>; COUNT]>,
}


pub trait PoolAcquire<T: Send + Clone> {
    fn acquire(&self, initial_ref_count: u8) -> Option<PoolSlot<T>>;
    //fn is_full(&self) -> bool;
}
pub trait PoolRelease {
    fn release(&self, handle: Handle);
}
pub trait PoolReleaseMandatory {
    fn release_mandatory(&self, handle: Handle);
} 

unsafe impl<T: Send + Clone, const COUNT: usize> Send for MemPool<T, COUNT> {}
unsafe impl<T: Send + Clone, const COUNT: usize> Sync for MemPool<T, COUNT> {}

impl<T: Send + Clone, const COUNT: usize> MemPool<T, COUNT> {
    pub fn new() -> Self {
        const { assert!(COUNT > 0 && COUNT < u16::MAX as usize - 1, "COUNT must be greater than 0 and less than u16::MAX - 1"); }
        Self {
            state: spin::Mutex::new(PoolState {
                slots_free_count: COUNT,
                slots_free      : std::array::from_fn(|i| (i as u16) + 1), // [1, 2, 3, ..., COUNT]
                slots_ref_counts: std::array::from_fn(|_| 0),
            }),
            bodies: unsafe { Box::<[UnsafeCell<MaybeUninit<T>>; COUNT]>::new_uninit().assume_init() },
        }
    }
}

impl<T: Send + Clone, const COUNT: usize> PoolAcquire<T> for MemPool<T, COUNT> {
    fn acquire(&self, initial_ref_count: u8) -> Option<PoolSlot<T>> {
        if initial_ref_count != 0 {
            let mut state = self.state.lock();
            if state.slots_free_count != 0 {
                state.slots_free_count -= 1;
                let handle = Handle(state.slots_free[state.slots_free_count] as usize);
                let idx: usize = handle.0 as usize - 1;
                state.slots_ref_counts[idx] = initial_ref_count;
                return Some(PoolSlot::new(
                    handle,
                    self.bodies[idx].get() as *mut T,
                ));
            }
        }
        None
    }

    /*fn is_full(&self) -> bool {
        let state = self.state.lock();
        state.slots_free_count == 0
    }*/
}

impl<T: Send + Clone, const COUNT: usize> PoolRelease for MemPool<T, COUNT> {
    fn release(&self, handle: Handle) {
        if handle.0 > 0  && handle.0 <= COUNT {
            let idx: usize = handle.0 as usize - 1;
            let mut state = self.state.lock();
            match state.slots_ref_counts[idx] {
                0 => {
                    unreachable!("release of zero-refcounted handle");
                }
                1 => {
                    state.slots_ref_counts[idx] = 0;
                    let free_idx = state.slots_free_count;
                    state.slots_free[free_idx] = handle.0 as u16;
                    state.slots_free_count += 1;
                }
                _ => {
                    state.slots_ref_counts[idx] -= 1;
                }
            }
        }
    }
}

impl<T: Send + Clone, const COUNT: usize> PoolReleaseMandatory for MemPool<T, COUNT> {
    fn release_mandatory(&self, handle: Handle) {
        if handle.0 > 0  && handle.0 <= COUNT {
            let idx: usize = handle.0 as usize - 1;
            let mut state = self.state.lock();
            if state.slots_ref_counts[idx] == 0 {
                unreachable!("release of zero-refcounted handle");
            } else {
                state.slots_ref_counts[idx] = 0;
                let free_idx = state.slots_free_count;
                state.slots_free[free_idx] = handle.0 as u16;
                state.slots_free_count += 1;
            }
        }
    }
}
