use std::marker::PhantomData;
use std::mem::size_of;

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

