use derive_more::derive::Constructor;

#[derive(Debug, Clone, PartialEq, Eq)] pub enum Endian
{
    Big, Little
}

#[derive(Debug, Constructor, Clone, Eq, PartialEq)] pub struct Register
{
    pub name: &'static str,
    pub size: u8,
}

/// This is based off of which architecture has the most registers,
/// future proofing for later expansion; RISC-V has 8 general and 8 floating.
pub const MAX_PARAMETERS: usize = 16;

#[derive(Debug, Constructor, Clone, Eq, PartialEq)] pub struct CallingConvention
{
    pub parameters: [Register; MAX_PARAMETERS],
    pub returns:     Register
}

pub const PADDING_REGISTER: Register = Register::new("__unused__", 0);

#[derive(Debug, Constructor, Clone, Eq, PartialEq)] pub struct Arch
{
    pub name:   &'static str,
    pub endian: Endian,

    pub calling_convention: CallingConvention,
    pub stack_pointer:      Register,
    pub word_size:          u16,
    pub page_size:          usize,
    pub stack_base:         u64,
    pub stack_size:         usize,
    pub heap_addr:          u64,
    pub max_mmap_size:      usize,
    pub cononical_mask:     u64
}

impl Arch
{
    pub fn validate_address(&self, addr: u64)
        -> bool
    {
        (addr >> 47) == 0 || (addr >> 47) == 0x1FFFF
    }

    pub fn page_mask(&self)
        -> u64
    {
        !(self.page_size as u64 - 1)
    }


    pub fn align(&self, vaddr: u64)
        -> u64
    {
        vaddr & self.page_mask()
    }

    pub fn page_align(&self, addr: u64)
        -> Option<u64>
    {
        if addr & self.cononical_mask != 0
        && addr & self.cononical_mask != self.cononical_mask
        {
            return None
        }

        Some(self.align(addr))
    }

    pub fn validate_segment(&self, vaddr: u64, size: usize, align: u64)
        -> bool
    {   // Validate segment doesn't exceed architectural limits
        vaddr.checked_add(size as u64)
            .map(|end| self.validate_address(vaddr) && 
                      self.validate_address(end) &&
                      align.is_power_of_two())
            .unwrap_or(false)
    }
}

pub const X86_64: Arch =
{
    let parameters =
    [
        Register::new("rdi", 64),
        Register::new("rsi", 64),
        Register::new("rdx", 64),
        Register::new("rcx", 64),
        Register::new("r8", 64),
        Register::new("r9", 64),
        Register::new("xmm0", 128),
        Register::new("xmm1", 128),
        Register::new("xmm2", 128),
        Register::new("xmm3", 128),
        Register::new("xmm4", 128),
        Register::new("xmm5", 128),
        Register::new("xmm6", 128),
        Register::new("xmm7", 128),
        // Register padding to meet max parameters.
        PADDING_REGISTER,
        PADDING_REGISTER
    ];

    let returns     = Register::new("rax", 64);
    let stack_ptr   = Register::new("rsp", 64);

        Arch
        {
            name:   "X86_64",
            endian: Endian::Little,

            calling_convention:     CallingConvention::new(parameters, returns),
            stack_pointer:          stack_ptr,
            word_size:              64,
            page_size:              0x1000,
            stack_base:             0x7FFF_FFFF_F000,
            stack_size:             8 * 0x400 * 0x400,
            heap_addr:              0x6000_0000_0000,
            max_mmap_size:          0x7FFF_0000,
            cononical_mask:         0x7FFF_FFFF_F000,
    }
};
