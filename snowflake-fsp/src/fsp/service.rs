use std::marker::PhantomData;
use std::ptr::NonNull;
use winfsp_sys::FSP_SERVICE;

pub struct FspService<T>(pub NonNull<FSP_SERVICE>, PhantomData<T>);

impl<T> FspService<T> {
    pub unsafe fn from_raw_unchecked(raw: *mut FSP_SERVICE) -> Self {
        unsafe { FspService(NonNull::new_unchecked(raw), Default::default()) }
    }

    pub fn set_context(&mut self, context: Box<T>) {
        let ptr = Box::into_raw(context);
        unsafe {
            self.0.as_mut().UserContext = ptr as *mut _;
        }
    }

    pub fn get_context(&mut self) -> Option<&mut T> {
        unsafe { self.0.as_mut().UserContext.cast::<T>().as_mut() }
    }
}
