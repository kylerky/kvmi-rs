use std::marker::PhantomData;
use std::mem::{self, size_of};
use std::slice::from_raw_parts;

pub struct VecBuf<T> {
    v: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> VecBuf<T>
where
    T: Sized,
{
    pub fn new() -> Self {
        let mut v = Vec::with_capacity(size_of::<T>());
        v.resize(size_of::<T>(), 0u8);
        Self {
            v,
            _marker: PhantomData,
        }
    }

    pub fn new_array(n: usize) -> Self {
        let sz = size_of::<T>() * n;
        let mut v = Vec::with_capacity(sz);
        v.resize(sz, 0u8);
        Self {
            v,
            _marker: PhantomData,
        }
    }

    pub unsafe fn as_mut_type(&mut self) -> &mut T {
        self.v.as_mut_ptr().cast::<T>().as_mut().unwrap()
    }

    pub unsafe fn nth_as_mut_type(&mut self, idx: usize) -> &mut T {
        self.v
            .as_mut_ptr()
            .cast::<T>()
            .offset(idx as isize)
            .as_mut()
            .unwrap()
    }
}

impl<T> From<VecBuf<T>> for Vec<u8> {
    fn from(b: VecBuf<T>) -> Self {
        b.v
    }
}

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
