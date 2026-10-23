use std::cell::UnsafeCell;
use std::mem::MaybeUninit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle(pub usize);

pub struct PoolSlot<T: Send + Clone> {
    pub handle: Handle,
    pub body  : *mut T,
    pool      : &'static dyn IPoolRefChanger,
}

impl<T: Send + Clone> PoolSlot<T> {
    fn new(handle: Handle, body: *mut T, pool: &'static dyn IPoolRefChanger) -> Self {
        Self { handle, body, pool }
    }
}

impl<T: Send + Clone> Clone for PoolSlot<T> {
    fn clone(&self) -> Self {
        self.pool.add_ref(self.handle);
        Self {
            handle: self.handle,
            body  : self.body,
            pool  : self.pool,
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
    bodies: Box<[UnsafeCell<MaybeUninit<T>>; COUNT]>,//unsafe impl<T: Send + Clone> Sync for PoolSlot<T> {}

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
            Some(PoolSlot::new(handle, self.bodies[idx].get() as *mut T, self))
        }
    }

    /*fn is_full(&self) -> bool {
        let state = self.state.lock();
        state.slots_free_count == 0
    }*/
}

/// Кадры крупнее этого порога в пул не возвращаются: один большой кадр
/// иначе навсегда занимает буфер.
const PACKET_BUF_KEEP: usize = 4096;
/// Сколько свободных буферов держать. Совпадает с глубиной очереди capture → parser.
const PACKET_BUF_POOL_MAX: usize = 512;

static PACKET_BUFS: spin::Mutex<Vec<Vec<u8>>> = spin::Mutex::new(Vec::new());

/// Буфер под копию кадра. Кадр длиннее 4 КБ получает обычный `Vec` и в пул не возвращается.
pub fn take_packet_buf(len: usize) -> Vec<u8> {
    if len > PACKET_BUF_KEEP {
        return Vec::with_capacity(len);
    }
    let recycled = {
        let mut pool = PACKET_BUFS.lock();
        pool.pop()
    };
    match recycled {
        Some(mut buf) => {
            buf.clear();
            if buf.capacity() < len {
                buf.reserve(len);
            }
            buf
        }
        None => Vec::with_capacity(len),
    }
}

/// Возвращает буфер после разбора. Слишком большой или лишний буфер освобождается.
pub fn recycle_packet_buf(mut buf: Vec<u8>) {
    if buf.capacity() == 0 || buf.capacity() > PACKET_BUF_KEEP {
        return;
    }
    buf.clear();
    let mut pool = PACKET_BUFS.lock();
    if pool.len() < PACKET_BUF_POOL_MAX {
        pool.push(buf);
    }
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
}
