#[cfg(feature = "read")]
use alloc::vec::Vec;
use core::fmt;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr;
use core::slice;

/// Marker trait for types that can be used as backing storage when a growable array type is needed.
///
/// This trait is sealed and cannot be implemented for types outside this crate.
pub trait ArrayLike: ArrayLikeSealed {}

pub(crate) use sealed::*;
mod sealed {
    use core::mem::MaybeUninit;
    use core::ops::{Deref, DerefMut};

    pub trait ArrayLikeSealed {
        /// The type of item stored in the array.
        type Item: Clone;

        /// The container for the array.
        ///
        /// This allows us keep `ArrayVec` as an implementation detail.
        type Storage: ArrayLikeStorage<Self::Item>;
    }

    pub trait ArrayLikeStorage<T: Clone>: Default + Clone + Deref<Target = [T]> + DerefMut {
        fn len(&self) -> usize;
        fn get(&self, index: usize) -> Option<&T>;
        fn clear(&mut self);
        fn pop(&mut self) -> Option<T>;
        fn try_push(&mut self, value: T) -> Result<(), CapacityFull>;
        fn try_insert(&mut self, index: usize, element: T) -> Result<(), CapacityFull>;
        fn swap_remove(&mut self, index: usize) -> T;
    }

    /// A trait for types that can be used in `ArrayVec`.
    ///
    /// SAFETY: Implementer must not modify the content in storage.
    pub unsafe trait Array {
        type Item: Clone;
        fn new_storage() -> Self;
        fn as_slice(&self) -> &[MaybeUninit<Self::Item>];
        fn as_mut_slice(&mut self) -> &mut [MaybeUninit<Self::Item>];
    }

    #[derive(Clone, Copy, Debug)]
    pub struct CapacityFull;

    pub struct ArrayVec<A: Array> {
        pub(super) storage: A,
        pub(super) len: usize,
    }
}

// Use macro since const generics can't be used due to MSRV.
macro_rules! impl_array {
    () => {};
    ($n:literal $($rest:tt)*) => {
        // SAFETY: does not modify the content in storage.
        unsafe impl<T: Clone> Array for [MaybeUninit<T>; $n] {
            type Item = T;

            fn new_storage() -> Self {
                // SAFETY: An uninitialized `[MaybeUninit<_>; _]` is valid.
                unsafe { MaybeUninit::uninit().assume_init() }
            }

            fn as_slice(&self) -> &[MaybeUninit<T>] {
                &self[..]
            }

            fn as_mut_slice(&mut self) -> &mut [MaybeUninit<T>] {
                &mut self[..]
            }
        }

        impl<T: Clone> ArrayLike for [T; $n] {}
        impl<T: Clone> ArrayLikeSealed for [T; $n] {
            type Item = T;
            type Storage = ArrayVec<[MaybeUninit<T>; $n]>;
        }

        impl_array!($($rest)*);
    }
}

impl_array!(0 1 2 3 4 8 16 32 64 128 192);

#[cfg(feature = "read")]
impl<T: Clone> ArrayLike for Vec<T> {}
#[cfg(feature = "read")]
impl<T: Clone> ArrayLikeSealed for Vec<T> {
    type Item = T;
    type Storage = Vec<T>;
}

#[cfg(feature = "read")]
impl<T: Clone> ArrayLikeStorage<T> for Vec<T> {
    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn get(&self, index: usize) -> Option<&T> {
        self.as_slice().get(index)
    }

    fn clear(&mut self) {
        Vec::clear(self)
    }

    fn pop(&mut self) -> Option<T> {
        Vec::pop(self)
    }

    fn try_push(&mut self, value: T) -> Result<(), CapacityFull> {
        Vec::push(self, value);
        Ok(())
    }

    fn try_insert(&mut self, index: usize, element: T) -> Result<(), CapacityFull> {
        Vec::insert(self, index, element);
        Ok(())
    }

    fn swap_remove(&mut self, index: usize) -> T {
        Vec::swap_remove(self, index)
    }
}

impl<A: Array> ArrayVec<A> {
    pub(crate) fn new() -> Self {
        Self {
            storage: A::new_storage(),
            len: 0,
        }
    }
}

impl<A: Array> ArrayLikeStorage<A::Item> for ArrayVec<A> {
    fn len(&self) -> usize {
        self.len
    }

    fn get(&self, index: usize) -> Option<&A::Item> {
        self.deref().get(index)
    }

    fn clear(&mut self) {
        let ptr: *mut [A::Item] = &mut **self;
        // Set length first so the type invariant is upheld even if `drop_in_place` panicks.
        self.len = 0;
        // SAFETY: `ptr` contains valid elements only and we "forget" them by setting the length.
        unsafe { ptr::drop_in_place(ptr) };
    }

    fn try_push(&mut self, value: A::Item) -> Result<(), CapacityFull> {
        let storage = A::as_mut_slice(&mut self.storage);
        if self.len >= storage.len() {
            return Err(CapacityFull);
        }

        storage[self.len] = MaybeUninit::new(value);
        self.len += 1;
        Ok(())
    }

    fn try_insert(&mut self, index: usize, element: A::Item) -> Result<(), CapacityFull> {
        assert!(index <= self.len);

        let storage = A::as_mut_slice(&mut self.storage);
        if self.len >= storage.len() {
            return Err(CapacityFull);
        }

        // SAFETY: storage[index] is filled later.
        unsafe {
            let p = storage.as_mut_ptr().add(index);
            core::ptr::copy(p as *const _, p.add(1), self.len - index);
        }
        storage[index] = MaybeUninit::new(element);
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<A::Item> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            // SAFETY: this element is valid and we "forget" it by setting the length.
            Some(unsafe { A::as_slice(&self.storage)[self.len].as_ptr().read() })
        }
    }

    fn swap_remove(&mut self, index: usize) -> A::Item {
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

impl<A: Array> Deref for ArrayVec<A> {
    type Target = [A::Item];

    fn deref(&self) -> &[A::Item] {
        let slice = &A::as_slice(&self.storage);
        debug_assert!(self.len <= slice.len());
        // SAFETY: valid elements.
        unsafe { slice::from_raw_parts(slice.as_ptr() as _, self.len) }
    }
}

impl<A: Array> DerefMut for ArrayVec<A> {
    fn deref_mut(&mut self) -> &mut [A::Item] {
        let slice = &mut A::as_mut_slice(&mut self.storage);
        debug_assert!(self.len <= slice.len());
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
