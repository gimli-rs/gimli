use core::fmt;
use core::mem::MaybeUninit;
use core::ops;
use core::ptr;
use core::slice;

// Use a helper trait since const generics can't be used due to MSRV.
// SAFETY: Implementer must not modify the content in storage.
pub(crate) unsafe trait Array {
    type Item;
    type Storage;

    fn new_storage() -> Self::Storage;
    fn as_slice(storage: &Self::Storage) -> &[MaybeUninit<Self::Item>];
    fn as_mut_slice(storage: &mut Self::Storage) -> &mut [MaybeUninit<Self::Item>];
}

macro_rules! impl_array {
    () => {};
    ($n:literal $($rest:tt)*) => {
        // SAFETY: does not modify the content in storage.
        unsafe impl<T> Array for [T; $n] {
            type Item = T;
            type Storage = [MaybeUninit<T>; $n];

            fn new_storage() -> Self::Storage {
                // SAFETY: An uninitialized `[MaybeUninit<_>; _]` is valid.
                unsafe { MaybeUninit::uninit().assume_init() }
            }

            fn as_slice(storage: &Self::Storage) -> &[MaybeUninit<T>] {
                storage
            }

            fn as_mut_slice(storage: &mut Self::Storage) -> &mut [MaybeUninit<T>] {
                storage
            }
        }
        impl_array!($($rest)*);
    }
}

impl_array!(4 192);

pub(crate) struct ArrayVec<A: Array> {
    storage: A::Storage,
    len: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CapacityFull;

impl<A: Array> ArrayVec<A> {
    pub fn new() -> Self {
        Self {
            storage: A::new_storage(),
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        let ptr: *mut [A::Item] = &mut **self;
        // Set length first so the type invariant is upheld even if `drop_in_place` panicks.
        self.len = 0;
        // SAFETY: `ptr` contains valid elements only and we "forget" them by setting the length.
        unsafe { ptr::drop_in_place(ptr) };
    }

    pub fn try_push(&mut self, value: A::Item) -> Result<(), CapacityFull> {
        let storage = A::as_mut_slice(&mut self.storage);
        if self.len >= storage.len() {
            return Err(CapacityFull);
        }

        storage[self.len] = MaybeUninit::new(value);
        self.len += 1;
        Ok(())
    }

    pub fn try_insert(&mut self, index: usize, element: A::Item) -> Result<(), CapacityFull> {
        assert!(index <= self.len);

        let storage = A::as_mut_slice(&mut self.storage);
        if self.len >= storage.len() {
            return Err(CapacityFull);
        }

        // SAFETY: storage[index] is filled later.
        unsafe {
            let p = storage.as_mut_ptr().add(index);
            core::ptr::copy(p, p.add(1), self.len - index);
        }
        storage[index] = MaybeUninit::new(element);
        self.len += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<A::Item> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            // SAFETY: this element is valid and we "forget" it by setting the length.
            Some(unsafe { A::as_slice(&mut self.storage)[self.len].as_ptr().read() })
        }
    }

    pub fn swap_remove(&mut self, index: usize) -> A::Item {
        assert!(self.len > 0);
        A::as_mut_slice(&mut self.storage).swap(index, self.len - 1);
        self.pop().unwrap()
    }
}

impl<A: Array> Drop for ArrayVec<A> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<A: Array> Default for ArrayVec<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Array> ops::Deref for ArrayVec<A> {
    type Target = [A::Item];

    fn deref(&self) -> &[A::Item] {
        let slice = &A::as_slice(&self.storage);
        // SAFETY: valid elements.
        unsafe { slice::from_raw_parts(slice.as_ptr() as _, self.len) }
    }
}

impl<A: Array> ops::DerefMut for ArrayVec<A> {
    fn deref_mut(&mut self) -> &mut [A::Item] {
        let slice = &mut A::as_mut_slice(&mut self.storage);
        // SAFETY: valid elements.
        unsafe { slice::from_raw_parts_mut(slice.as_mut_ptr() as _, self.len) }
    }
}

impl<A: Array> Clone for ArrayVec<A>
where
    A::Item: Clone,
{
    fn clone(&self) -> Self {
        let mut new = Self::default();
        for value in &**self {
            new.try_push(value.clone()).unwrap();
        }
        new
    }
}

impl<A: Array> PartialEq for ArrayVec<A>
where
    A::Item: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<A: Array> Eq for ArrayVec<A> where A::Item: Eq {}

impl<A: Array> fmt::Debug for ArrayVec<A>
where
    A::Item: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
