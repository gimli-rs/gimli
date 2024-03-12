#[cfg(feature = "read")]
use alloc::boxed::Box;
#[cfg(feature = "read")]
use alloc::vec::Vec;
use core::fmt;
use core::mem::MaybeUninit;
use core::ops;
use core::ptr;
use core::slice;

mod sealed {
    /// # Safety
    /// Implementer must not modify the content in storage.
    pub unsafe trait Sealed {
        type Storage;

        fn new_storage() -> Self::Storage;

        fn grow(_storage: &mut Self::Storage, _additional: usize) -> Result<(), CapacityFull> {
            Err(CapacityFull)
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct CapacityFull;
}

use sealed::*;

/// Marker trait for types that can be used as backing storage when a growable array type is needed.
///
/// This trait is sealed and cannot be implemented for types outside this crate.
pub trait ArrayLike: Sealed {
    /// Type of the elements being stored.
    type Item;

    #[doc(hidden)]
    type OtherArray<OtherItem>: ArrayLike<Item = OtherItem>;

    #[doc(hidden)]
    fn convert<I2>(old: <Self as Sealed>::Storage) -> <Self::OtherArray<I2> as Sealed>::Storage;

    #[doc(hidden)]
    fn as_slice(storage: &Self::Storage) -> &[MaybeUninit<Self::Item>];

    #[doc(hidden)]
    fn as_mut_slice(storage: &mut Self::Storage) -> &mut [MaybeUninit<Self::Item>];
}

// Use macro since const generics can't be used due to MSRV.
macro_rules! impl_array {
    () => {};
    ($n:literal $($rest:tt)*) => {
        // SAFETY: does not modify the content in storage.
        unsafe impl<T> Sealed for [T; $n] {
            type Storage = [MaybeUninit<T>; $n];

            fn new_storage() -> Self::Storage {
                // SAFETY: An uninitialized `[MaybeUninit<_>; _]` is valid.
                unsafe { MaybeUninit::uninit().assume_init() }
            }
        }

        impl<T> ArrayLike for [T; $n] {
            type Item = T;

            type OtherArray<OtherType> = [OtherType; $n];

            fn convert<T2>(_old: [MaybeUninit<T>; $n]) -> [MaybeUninit<T2>; $n] {
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

#[cfg(feature = "read")]
macro_rules! impl_box {
    () => {};
    ($n:literal $($rest:tt)*) => {
        // SAFETY: does not modify the content in storage.
        unsafe impl<T> Sealed for Box<[T; $n]> {
            type Storage = Box<[MaybeUninit<T>; $n]>;

            fn new_storage() -> Self::Storage {
                // SAFETY: An uninitialized `[MaybeUninit<_>; _]` is valid.
                Box::new(unsafe { MaybeUninit::uninit().assume_init() })
            }
        }

        impl<T> ArrayLike for Box<[T; $n]> {
            type Item = T;

            type OtherArray<OtherType> = Box<[OtherType; $n]>;

            fn convert<T2>(old: Box<[MaybeUninit<T>; $n]>) -> Box<[MaybeUninit<T2>; $n]> {
                // If T and T2 have the same layout (size and alignment), we can reuse the allocation.
                // In that case, convert the box into its raw pointer and then back into a box of the other type.
                // Otherwise, allocate a new box the same way as new_storage() does.
                if core::mem::size_of::<T>() == core::mem::size_of::<T2>()
                    && core::mem::align_of::<T>() == core::mem::align_of::<T2>()
                {
                    // SAFETY: The layout of T and T2 is the same.
                    unsafe { Box::from_raw(Box::into_raw(old) as *mut [MaybeUninit<T2>; $n]) }
                } else {
                    // SAFETY: An uninitialized `[MaybeUninit<_>; _]` is valid.
                    Box::new(unsafe { MaybeUninit::uninit().assume_init() })
                }
            }

            fn as_slice(storage: &Self::Storage) -> &[MaybeUninit<T>] {
                &storage[..]
            }

            fn as_mut_slice(storage: &mut Self::Storage) -> &mut [MaybeUninit<T>] {
                &mut storage[..]
            }
        }

        impl_box!($($rest)*);
    }
}

impl_array!(0 1 2 3 4 8 16 32 64 128 192);
#[cfg(feature = "read")]
impl_box!(0 1 2 3 4 8 16 32 64 128 192);

#[cfg(feature = "read")]
unsafe impl<T> Sealed for Vec<T> {
    type Storage = Box<[MaybeUninit<T>]>;

    fn new_storage() -> Self::Storage {
        Box::new([])
    }

    fn grow(storage: &mut Self::Storage, additional: usize) -> Result<(), CapacityFull> {
        let mut vec: Vec<_> = core::mem::replace(storage, Box::new([])).into();
        vec.reserve(additional);
        // SAFETY: This is a `Vec` of `MaybeUninit`.
        unsafe { vec.set_len(vec.capacity()) };
        *storage = vec.into_boxed_slice();
        Ok(())
    }
}

#[cfg(feature = "read")]
impl<T> ArrayLike for Vec<T> {
    type Item = T;

    type OtherArray<OtherType> = Vec<OtherType>;

    fn convert<T2>(old: Box<[MaybeUninit<T>]>) -> Box<[MaybeUninit<T2>]> {
        let mut vec: Vec<_> = old.into();
        vec.clear();
        let mut vec: Vec<MaybeUninit<T2>> = vec.into_iter().map(|_| unreachable!()).collect();
        // SAFETY: This is a `Vec` of `MaybeUninit`.
        unsafe { vec.set_len(vec.capacity()) };
        vec.into_boxed_slice()
    }

    fn as_slice(storage: &Self::Storage) -> &[MaybeUninit<T>] {
        storage
    }

    fn as_mut_slice(storage: &mut Self::Storage) -> &mut [MaybeUninit<T>] {
        storage
    }
}

pub(crate) struct ArrayVec<A: ArrayLike> {
    /// always Some() unless a consuming method (like `clear_and_recycle`) has been called.
    storage: Option<A::Storage>,
    len: usize,
}

impl<A: ArrayLike> ArrayVec<A> {
    pub fn new() -> Self {
        Self {
            storage: Some(A::new_storage()),
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        if self.len == 0 {
            return;
        }
        let ptr: *mut [A::Item] = &mut **self;
        // Set length first so the type invariant is upheld even if `drop_in_place` panicks.
        self.len = 0;
        // SAFETY: `ptr` contains valid elements only and we "forget" them by setting the length.
        unsafe { ptr::drop_in_place(ptr) };
    }

    pub fn clear_and_recycle<T2>(mut self) -> ArrayVec<A::OtherArray<T2>> {
        self.clear();

        ArrayVec {
            storage: Some(A::convert(self.storage.take().unwrap())),
            len: 0,
        }
    }

    pub fn try_push(&mut self, value: A::Item) -> Result<(), CapacityFull> {
        let mut storage = A::as_mut_slice(self.storage.as_mut().unwrap());
        if self.len >= storage.len() {
            A::grow(self.storage.as_mut().unwrap(), 1)?;
            storage = A::as_mut_slice(self.storage.as_mut().unwrap());
        }

        storage[self.len] = MaybeUninit::new(value);
        self.len += 1;
        Ok(())
    }

    pub fn try_insert(&mut self, index: usize, element: A::Item) -> Result<(), CapacityFull> {
        assert!(index <= self.len);

        let mut storage = A::as_mut_slice(self.storage.as_mut().unwrap());
        if self.len >= storage.len() {
            A::grow(self.storage.as_mut().unwrap(), 1)?;
            storage = A::as_mut_slice(self.storage.as_mut().unwrap());
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

    pub fn pop(&mut self) -> Option<A::Item> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            // SAFETY: this element is valid and we "forget" it by setting the length.
            Some(unsafe {
                A::as_slice(self.storage.as_ref().unwrap())[self.len]
                    .as_ptr()
                    .read()
            })
        }
    }

    pub fn swap_remove(&mut self, index: usize) -> A::Item {
        assert!(self.len > 0);
        A::as_mut_slice(self.storage.as_mut().unwrap()).swap(index, self.len - 1);
        self.pop().unwrap()
    }
}

#[cfg(feature = "read")]
impl<T> ArrayVec<Vec<T>> {
    pub fn into_vec(mut self) -> Vec<T> {
        let len = core::mem::replace(&mut self.len, 0);
        let storage = core::mem::take(&mut self.storage).unwrap();
        let slice = Box::leak(storage);
        debug_assert!(len <= slice.len());
        // SAFETY: valid elements.
        unsafe { Vec::from_raw_parts(slice.as_mut_ptr() as *mut T, len, slice.len()) }
    }
}

impl<A: ArrayLike> Drop for ArrayVec<A> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<A: ArrayLike> Default for ArrayVec<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: ArrayLike> ops::Deref for ArrayVec<A> {
    type Target = [A::Item];

    fn deref(&self) -> &[A::Item] {
        let slice = &A::as_slice(self.storage.as_ref().unwrap());
        debug_assert!(self.len <= slice.len());
        // SAFETY: valid elements.
        unsafe { slice::from_raw_parts(slice.as_ptr() as _, self.len) }
    }
}

impl<A: ArrayLike> ops::DerefMut for ArrayVec<A> {
    fn deref_mut(&mut self) -> &mut [A::Item] {
        let slice = &mut A::as_mut_slice(self.storage.as_mut().unwrap());
        debug_assert!(self.len <= slice.len());
        // SAFETY: valid elements.
        unsafe { slice::from_raw_parts_mut(slice.as_mut_ptr() as _, self.len) }
    }
}

impl<A: ArrayLike> Clone for ArrayVec<A>
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

impl<A: ArrayLike> PartialEq for ArrayVec<A>
where
    A::Item: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<A: ArrayLike> Eq for ArrayVec<A> where A::Item: Eq {}

impl<A: ArrayLike> fmt::Debug for ArrayVec<A>
where
    A::Item: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
