use std::marker::PhantomData;
use std::mem::{self, size_of};
use std::slice;

pub struct VecBuf<T> {
    v: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> Default for VecBuf<T> {
    fn default() -> Self {
        let v = vec![0u8; size_of::<T>()];
        Self {
            v,
            _marker: PhantomData,
        }
    }
}

impl<T> VecBuf<T>
where
    T: Sized,
{
    pub fn new() -> Self {
        Self::default()
    }
    pub fn new_array(n: usize) -> Self {
        let sz = size_of::<T>() * n;
        let v = vec![0u8; sz];
        Self {
            v,
            _marker: PhantomData,
        }
    }

    pub unsafe fn as_mut_type(&mut self) -> &mut T {
        self.v.as_mut_ptr().cast::<T>().as_mut().unwrap()
    }

    pub unsafe fn nth_as_mut_type(&mut self, idx: usize) -> &mut T {
        self.v.as_mut_ptr().cast::<T>().add(idx).as_mut().unwrap()
    }
}

impl<T> From<VecBuf<T>> for Vec<u8> {
    fn from(b: VecBuf<T>) -> Self {
        b.v
    }
}

/// # Safety
///
/// This function should be safe
/// to be called on any reference to a sized type.
pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    slice::from_raw_parts((p as *const T) as *const u8, size_of::<T>())
}

#[cfg(test)]
/// # Safety
///
/// This function should be safe
/// to be called on most reference to a sized type
/// but it may break gurantees made on the values
/// of some types.
pub unsafe fn any_as_mut_u8_slice<T: Sized>(p: &mut T) -> &mut [u8] {
    slice::from_raw_parts_mut((p as *mut T) as *mut u8, size_of::<T>())
}

pub fn any_vec_as_u8_vec<T>(mut vec: Vec<T>) -> Vec<u8> {
    unsafe {
        let ptr = vec.as_mut_ptr();
        let len = vec.len();
        let cap = vec.capacity();

        mem::forget(vec);

        let t_sz = size_of::<T>();
        Vec::from_raw_parts(ptr as *mut u8, len * t_sz, cap * t_sz)
    }
}

/// # Safety
///
/// O should be sized
/// and the size of s should be exactly the same as the
/// size of the intended type
///
/// Normally, T is u8
pub unsafe fn boxed_slice_to_type<T, O>(s: Box<[T]>) -> Box<O> {
    let p = Box::into_raw(s) as *mut O;
    Box::from_raw(p)
}
