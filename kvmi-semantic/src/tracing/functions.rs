use crate::event::kvm_regs;
use crate::memory::address_space::*;
use crate::{Error, Result, PTR_SZ};

use std::convert::TryInto;

pub struct MSx64<'a> {
    regs: &'a kvm_regs,
    stack_args: Vec<u64>,
}
impl<'a> MSx64<'a> {
    const REGS_NUM: usize = 4;
    pub async fn new(v_space: &IA32eVirtual, regs: &'a kvm_regs, num: usize) -> Result<MSx64<'a>> {
        if num > Self::REGS_NUM {
            let rsp = regs.rsp;
            let start_offset = ((Self::REGS_NUM + 1) * PTR_SZ) as u64;
            let args_bytes = v_space
                .read(rsp + start_offset, (num - Self::REGS_NUM) * PTR_SZ)
                .await?
                .ok_or(Error::InvalidVAddr)?;
            let stack_args: Vec<u64> = args_bytes[..]
                .chunks(PTR_SZ)
                .map(|bytes| u64::from_ne_bytes(bytes.try_into().unwrap()))
                .collect();
            Ok(Self { regs, stack_args })
        } else {
            Ok(Self {
                regs,
                stack_args: vec![],
            })
        }
    }

    pub fn get(&self, idx: usize) -> Option<&u64> {
        match idx {
            0 => Some(&self.regs.rcx),
            1 => Some(&self.regs.rdx),
            2 => Some(&self.regs.r8),
            3 => Some(&self.regs.r9),
            idx => self.stack_args.get(idx - Self::REGS_NUM),
        }
    }
}
