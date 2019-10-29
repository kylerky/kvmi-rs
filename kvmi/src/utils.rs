use std::marker::PhantomData;
use std::mem::{self, size_of};
use std::slice::from_raw_parts;

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
    from_raw_parts((p as *const T) as *const u8, size_of::<T>())
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
