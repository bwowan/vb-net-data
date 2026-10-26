use std::cell::UnsafeCell;
use std::mem::MaybeUninit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle(pub usize);

/// Сколько байт сырого кадра хранит слот. Более длинный кадр обрезается до этого размера.
pub const PACKET_BUF_KEEP: usize = 4096;

pub struct PoolSlot<T: Send + Clone> {
    pub handle  : Handle,
    pub body    : *mut T,
    pub bin     : *mut [u8; PACKET_BUF_KEEP],
    pub cap_len : usize,
    pub orig_len: usize,
    pool        : &'static dyn IPoolRefChanger,
}

impl<T: Send + Clone> PoolSlot<T> {
    fn new(
        handle: Handle,
        body: *mut T,
        bin: *mut [u8; PACKET_BUF_KEEP],
        pool: &'static dyn IPoolRefChanger,
    ) -> Self {
        Self {
            handle,
            body,
            bin,
            cap_len: 0,
            orig_len: 0,
            pool,
        }
    }
}

impl<T: Send + Clone> Clone for PoolSlot<T> {
    fn clone(&self) -> Self {
        self.pool.add_ref(self.handle);
        Self {
            handle  : self.handle,
            body    : self.body,
            bin     : self.bin,
            cap_len : self.cap_len,
            orig_len: self.orig_len,
            pool    : self.pool,
        }
    }
}

impl<T: Send + Clone> Drop for PoolSlot<T> {
    fn drop(&mut self) {
        self.pool.del_ref(self.handle);
    }
}

unsafe impl<T: Send + Clone> Send for PoolSlot<T> {}

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
    bins  : Box<[UnsafeCell<MaybeUninit<[u8; PACKET_BUF_KEEP]>>; COUNT]>,
}


pub trait PoolAcquire<T: Send + Clone> {
    fn acquire(&'static self) -> Option<PoolSlot<T>>;
    //fn is_full(&self) -> bool;
}
pub trait IPoolRefChanger {
    fn add_ref(&self, handle: Handle);
    fn del_ref(&self, handle: Handle);
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
            bins  : unsafe { Box::<[UnsafeCell<MaybeUninit<[u8; PACKET_BUF_KEEP]>>; COUNT]>::new_uninit().assume_init() },
        }
    }
}

impl<T: Send + Clone, const COUNT: usize> PoolAcquire<T> for MemPool<T, COUNT> {
    fn acquire(&'static self) -> Option<PoolSlot<T>> {
        let mut state = self.state.lock();
        if state.slots_free_count == 0 {
            None
        } else {
            state.slots_free_count -= 1;
            let handle = Handle(state.slots_free[state.slots_free_count] as usize);
            let idx: usize = handle.0 as usize - 1;
            state.slots_ref_counts[idx] = 1;
            Some(PoolSlot::new(
                handle,
                self.bodies[idx].get() as *mut T,
                self.bins[idx].get() as *mut [u8; PACKET_BUF_KEEP],
                self,
            ))
        }
    }

    /*fn is_full(&self) -> bool {
        let state = self.state.lock();
        state.slots_free_count == 0
    }*/
}

impl<T: Send + Clone, const COUNT: usize> IPoolRefChanger for MemPool<T, COUNT> {
    fn add_ref(&self, handle: Handle) {
        if handle.0 > 0 && handle.0 <= COUNT {
            let idx: usize = handle.0 as usize - 1;
            let mut state = self.state.lock();
            match state.slots_ref_counts[idx] {
                0 => unreachable!("add_ref of zero-refcounted handle"),
                u8::MAX => unreachable!("add_ref overflow"),
                n => state.slots_ref_counts[idx] = n + 1,
            }
        }
    }

    fn del_ref(&self, handle: Handle) {
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


#[cfg(test)]
mod tests {
    use super::*;

    /// Слот занят, пока жива хотя бы одна копия. В пул он возвращается после Drop последней.
    #[test]
    fn slot_released_when_last_copy_drops() {
        let pool: &'static MemPool<u32, 1> = Box::leak(Box::new(MemPool::new()));
        let slot = pool.acquire().expect("empty pool");
        assert!(pool.acquire().is_none(), "only slot is still held");
        let copy = slot.clone();
        drop(slot);
        assert!(pool.acquire().is_none(), "clone still holds the slot");
        drop(copy);
        let again = pool.acquire().expect("last drop returned the slot");
        drop(again);
    }

    /// У каждого слота свой буфер кадра. В него пишется префикс, длины копируются вместе со слотом.
    #[test]
    fn slots_have_distinct_writable_bins() {
        let pool: &'static MemPool<u32, 2> = Box::leak(Box::new(MemPool::new()));
        let mut first = pool.acquire().expect("first slot");
        let second = pool.acquire().expect("second slot");
        assert!(!std::ptr::eq(first.bin, second.bin), "slots share one bin");
        unsafe {
            first.bin.cast::<u8>().write(0xAB);
            second.bin.cast::<u8>().write(0xCD);
        }
        assert_eq!(unsafe { first.bin.cast::<u8>().read() }, 0xAB);
        assert_eq!(unsafe { second.bin.cast::<u8>().read() }, 0xCD);
        first.cap_len = 1;
        first.orig_len = 100;
        let copy = first.clone();
        assert_eq!(copy.cap_len, 1);
        assert_eq!(copy.orig_len, 100);
        assert!(std::ptr::eq(copy.bin, first.bin));
        drop(copy);
        drop(first);
        drop(second);
    }
}
