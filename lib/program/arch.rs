use std::sync::LazyLock;
use derive_more::derive::Constructor;

use crate::il::Scalar;

#[derive(Debug, Clone, PartialEq, Eq)] pub enum Endian
{
    Big, Little
}

#[derive(Debug, Constructor, Clone)] pub struct CallingConvention
{
    pub parameters: Vec<Scalar>,
    pub returns:    Scalar
}

#[derive(Debug, Constructor, Clone)] pub struct Arch
{
    pub name:   String,
    pub endian: Endian,

    pub calling_convention: CallingConvention,
    pub stack_pointer:      Scalar,
    pub word_size:          u16,
    pub page_size:          u32,
}

impl Eq for Arch {}
impl PartialEq for Arch
{
    fn eq(&self, other: &Self)
        -> bool
    {
        self.name           == other.name           &&
        self.endian         == other.endian         &&
        self.word_size      == other.word_size      &&
        self.stack_pointer  == other.stack_pointer
    }
}

pub static X86_64: LazyLock<Arch> = LazyLock::new(|| Arch::new("X86_64".into(), Endian::Little, CallingConvention::new(
        [Scalar::new("rdi", 64),     Scalar::new("rsi", 64), Scalar::new("rdx", 64),      Scalar::new("rcx", 64),
         Scalar::new("r8", 64),      Scalar::new("r9", 64), Scalar::new("xmm0", 64),      Scalar::new("xmm1", 64),
         Scalar::new("xmm2", 64),    Scalar::new("xmm3", 64), Scalar::new("xmm4", 64),    Scalar::new("xmm5", 64),
         Scalar::new("xmm6", 64),    Scalar::new("xmm7", 64)].to_vec(), Scalar::new("rax", 64)),
         Scalar::new("rsp", 64), 64, 4096));
