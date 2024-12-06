use std::{ cmp::Ordering, collections::BTreeMap, ops::Range };
use derive_more::derive::Constructor;
use rangemap::RangeMap;
use bitflags::bitflags;
use thiserror::Error;

use super::arch::Arch;

/// Architecture-specific memory management constants and configurations
pub mod arch_memory
{
    use crate::program::Arch;

    pub const PAGE_SIZE: usize          = 0x1000;
    pub const PAGE_MASK: u64            = !(PAGE_SIZE as u64 - 1);

    // X86_64 specific memory layout constants
    pub const CANONICAL_ADDR_MASK: u64  = 0xFFFF_8000_0000_0000;
    pub const STACK_BASE: u64           = 0x7FFF_FFFF_F000;
    pub const STACK_SIZE: usize         = 8 * 1024 * 1024;
    pub const HEAP_BASE: u64            = 0x6000_0000_0000;
    pub const MAX_MMAP_SIZE: usize      = 0x7FFF_0000;

    pub fn validate_address(addr: u64, arch: &Arch)
        -> bool
    {
        match arch.name.as_str()
        {
            "X86_64" => (addr >> 47) == 0 || (addr >> 47) == 0x1FFFF,
            _ => true // Default case for other architectures
        }
    }
}

#[derive(Error, Debug)] pub enum MemoryError
{
    #[error("invalid page access at {0:#x}")]                                   InvalidPage(u64),
    #[error("access violation at {0:#x}: {1}")]                                 AccessViolation(u64, String),
    #[error("alignment error at {0:#x} (required alignment: {1})")]             BadAlignment(u64, usize),
    #[error("out of bounds access at {0:#x} (size: {1})")]                      OutOfBounds(u64, usize),
    #[error(r#"tried allocating at an existing page, address of {0:#x}"#)]      PageExists(u64),
    #[error(r#"invalid size of {0:#x}"#)]                                       InvalidSize(usize),
    #[error("invalid address space: address {0:#x} is not canonical")]          NonCanonical(u64),
    #[error("memory region overlap at {0:#x}-{1:#x}")]                          Overlapping(u64, u64),
}

bitflags!
{
    #[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct PagePerms: u8
    {
        const READ      = 0b001;
        const WRITE     = 0b010;
        const EXECUTE   = 0b100;

        // Common permission combinations.
        const RW        = Self::READ.bits() | Self::WRITE.bits();
        const RX        = Self::READ.bits() | Self::EXECUTE.bits();
        const RWX       = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
    }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)] pub struct PageAddr(pub u64);
impl PageAddr
{
    pub fn new(addr: u64)
        -> Result<Self, MemoryError>
    {   // Validate canonical address form for x86_64.
        if addr & arch_memory::CANONICAL_ADDR_MASK != 0
            && addr & arch_memory::CANONICAL_ADDR_MASK != arch_memory::CANONICAL_ADDR_MASK
        {
            return Err(MemoryError::NonCanonical(addr));
        }

        Ok(Self(addr & arch_memory::PAGE_MASK))
    }

    pub fn addr(&self)
        -> u64
    {
        self.0
    }
}

impl Ord for PageAddr
{
    fn cmp(&self, other: &Self)
        -> Ordering
    {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for PageAddr
{
    fn partial_cmp(&self, other: &Self)
        -> Option<Ordering>
    {
        Some(self.cmp(other))
    }
}


#[derive(Debug, Constructor)] pub struct MemoryRegion
{
    pub data:       Vec<u8>,
    pub perms:      PagePerms,
    pub metadata:   MemoryMetadata,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Constructor)] pub struct MemoryMetadata
{   /// ELF section or segment name.
    pub name:           Option<String>,
    /// Original file offset for mapped content.
    pub file_offset:    Option<u64>,
    /// Size of original file data.
    pub file_size:      Option<u64>,
    /// Memory region type.
    pub region_type:    RegionType,
    /// Source module name/path.
    pub module:         Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)] pub enum RegionType
{
    Text, Data,
    Bss,  Stack,
    Heap, Shared,
    #[default] Other
}

#[derive(Debug)] pub struct Memory
{   /// Maps page-aligned addresses to allocated pages with their content and permissions
    /// BTreeMap ensures O(log n) lookups and ordered iteration capabilities
    pub regions:    BTreeMap<PageAddr, MemoryRegion>,

    /// Tracks memory ranges and their metadata using interval tree structure,
    /// provides efficient range queries and overlap detection.
    /// Key: address range, Value: associated metadata
    mapped_ranges:  RangeMap<u64, MemoryMetadata>,

    /// Reference to architecture specification,
    /// Controls address validation and memory layout constraints.
    arch:           Arch,
}

impl Memory
{
    pub fn new(arch: Arch)
        -> Self
    {
        Self
        {
            regions:        BTreeMap::new(),
            mapped_ranges:  RangeMap::new(),
            arch,
        }
    }

    /// Sets the `Module` page size.
    pub fn set_page_size(&mut self, page_size: u32)
    {
        self.arch.page_size = page_size
    }

    /// Allocates a new memory region with specified permissions and metadata
    /// Ensures:
    /// - No range overlaps
    /// - Valid addresses for architecture
    /// - Proper page alignment
    pub fn allocate(&mut self, addr: u64, size: usize, perms: PagePerms, metadata: MemoryMetadata)
        -> Result<(), MemoryError>
    {
        if size == 0 || size > arch_memory::MAX_MMAP_SIZE
        {
            return Err(MemoryError::InvalidSize(size))
        }

        let page_addr   = PageAddr::new(addr)?;
        let num_pages   = (size + arch_memory::PAGE_SIZE - 1) / arch_memory::PAGE_SIZE;
        let end_addr    = addr.checked_add((num_pages * arch_memory::PAGE_SIZE) as u64)
            .ok_or(MemoryError::OutOfBounds(addr, size))?;

        // Verify address validity for architecture.
        if !arch_memory::validate_address(addr, &self.arch)
        {
            return Err(MemoryError::NonCanonical(addr))
        }

        // Check for overlaps.
        if self.mapped_ranges.overlaps(&(addr..end_addr))
        {
            return Err(MemoryError::Overlapping(addr, end_addr))
        }

        // Allocate pages.
        for i in 0..num_pages
        {
            let curr_addr = PageAddr::new(page_addr.addr() + (i * arch_memory::PAGE_SIZE) as u64)?;

            if self.regions.contains_key(&curr_addr)
            {   // Rollback on failure.
                for j in 0..i
                {
                    let prev_addr = PageAddr::new(page_addr.addr() + (j * arch_memory::PAGE_SIZE) as u64)?;
                    self.regions.remove(&prev_addr);
                }
                // Remove the range from mapped_ranges
                self.mapped_ranges.remove(addr..end_addr);
                return Err(MemoryError::PageExists(curr_addr.addr()))
            }

            self.regions.insert(curr_addr, MemoryRegion::new(vec![0; arch_memory::PAGE_SIZE], perms, metadata.clone()));
        }

        // Record the range and metadata.
        self.mapped_ranges.insert(addr..end_addr, metadata);

        Ok(())
    }

    /// Find `MemoryMetadata` for an address of `addr`.
    pub fn get_metadata(&self, addr: u64)
        -> Option<&MemoryMetadata>
    {
        self.mapped_ranges.get_key_value(&addr)
            .map(|(_, metadata)| metadata)
    }

    /// Find regions that overlap with a given range.
    pub fn overlapping(&self, range: Range<u64>)
        -> impl Iterator<Item = (&Range<u64>, &MemoryMetadata)>
    {
        self.mapped_ranges.overlapping(range)
    }

    /// Free a memory region and its associated range tracking.
    pub fn free(&mut self, addr: u64)
        -> Result<(), MemoryError>
    {   // Find the range containing this address
        if let Some((range, _)) = self.mapped_ranges.get_key_value(&addr)
        {
            let range = range.clone();

            // Remove all pages in the range
            let num_pages = ((range.end - range.start) as usize) / arch_memory::PAGE_SIZE;
            for i in 0..num_pages
            {
                let curr_addr = PageAddr::new(addr + (i * arch_memory::PAGE_SIZE) as u64)?;
                self.regions.remove(&curr_addr);
            }

            // Remove the range tracking
            self.mapped_ranges.remove(range);

            return Ok(())
        }
        Err(MemoryError::InvalidPage(addr))
    }

    /// Retrieves an `Iterator` of mapped memory meta data ranges in order.
    pub fn mapped_ranges(&self)
        -> impl Iterator<Item = (&Range<u64>, &MemoryMetadata)>
    {
        self.mapped_ranges.iter()
    }

    /// Retrieves a `Vec` of bytes for the address of `addr` and `size`.
    pub fn read(&self, addr: u64, size: usize)
        -> Result<Vec<u8>, MemoryError>
    {
        let mut result          = Vec::with_capacity(size);
        let page_size           = self.arch.page_size as u64;
        let mut current_addr    = addr;
        let mut remaining       = size;

        while remaining > 0
        {
            let page_addr   = PageAddr::new(current_addr & !(page_size - 1))?;
            let offset      = (current_addr & (page_size - 1)) as usize;

            if let Some(region) = self.regions.get(&page_addr)
            {
                let read_size = std::cmp::min(remaining, page_size as usize - offset);
                result.extend_from_slice(&region.data[offset..offset + read_size]);

                remaining       -= read_size;
                current_addr    += read_size as u64;
            }
            else
            {
                return Err(MemoryError::InvalidPage(current_addr))
            }
        }

        Ok(result)
    }

    /// Copy `data` to address of `addr`.
    pub fn copy(&mut self, data: &[u8], addr: u64)
        -> Result<(), MemoryError>
    {
        let page_size           = self.arch.page_size as u64;
        let mut current_addr    = addr;
        let mut remaining       = data.len();
        let mut data_offset     = 0;

        while remaining > 0
        {
            let page_addr   = PageAddr::new(current_addr & !(page_size - 1))?;
            let offset      = (current_addr & (page_size - 1)) as usize;

            if let Some(region) = self.regions.get_mut(&page_addr)
            {
                let write_size  = std::cmp::min(remaining, page_size as usize - offset);

                region.data[offset..offset + write_size]
                    .copy_from_slice(&data[data_offset..data_offset + write_size]);

                remaining       -= write_size;
                current_addr    += write_size as u64;
                data_offset     += write_size;
            }
            else
            {
                return Err(MemoryError::InvalidPage(current_addr))
            }
        }
        Ok(())
    }
}
