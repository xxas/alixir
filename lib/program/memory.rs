use std::{ borrow::{Borrow, BorrowMut}, cell::RefCell, ops::Range };
use derive_more::derive::Constructor;
use rangemap::RangeMap;
use thiserror::Error;
use super::*;

#[derive(Error, Debug)] pub enum MemoryError
{
    #[error("Invalid page access at {0:#x}")]                           InvalidPage(u64),
    #[error("Access violation at {0:#x}: {1}")]                         AccessViolation(u64, String),
    #[error("Alignment error at {0:#x} (required alignment: {1})")]     BadAlignment(u64, usize),
    #[error("Out of bounds access at {0:#x} (size: {1})")]              OutOfBounds(u64, usize),
    #[error("Tried allocating inside another page: {0:#x}")]            PageExists(u64),
    #[error("invalid size of {0:#x}")]                                  Size(usize),
    #[error("Noncanonical address: {0:#x}")]                            Noncanonical(u64),
    #[error("Overlapping memory {0:#x}-{1:#x}")]                        Overlap(u64, u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)] pub enum RegionType
{
    Text, Data,
    Bss,  Stack,
    Heap, Shared,
    #[default] Other
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Constructor)] pub struct Metadata
{   /// Memory region type.
    pub region_type:    RegionType,
    /// Section range map.
    pub sections:       RangeMap<usize, String>,
    // Source module.
    pub module:         String,
}


#[derive(Debug, Constructor, PartialEq, Eq, Clone)] pub struct Page
{
    pub data:       RefCell<Vec<u8>>,
    pub metadata:   Metadata
}

pub struct Memory
{   // Pages of memory.
    pages:  RangeMap<u64, Page>,

    /// Architecture of the programs memory.
    arch:   Arch,
}

impl Memory
{
    pub fn new(arch: Arch)
        -> Self
    {
        Self
        {
            pages:  RangeMap::new(),
            arch,
        }
    }

    pub fn print_dump(&self)
    {
        for (range, page) in self.pages.iter()
        {
            let start_addr = range.start;
            let end_addr = range.end;
            let metadata = &page.metadata;
            let region = &metadata.region_type;
            let module = &metadata.module;
            let data = page.data.borrow();

            println!("Address Range: {:#x} - {:#x}", start_addr, end_addr);
            println!("Region Type: {:?}", region);
            println!("Module: {}", module);
            println!("Hex Dump:");

            for (i, byte) in data.iter().enumerate() {
                if i % 16 == 0
                {
                    print!("\n{:08x}: ", start_addr as usize + i);
                }
                print!("{:02x} ", byte);
            }

            println!("\n{}\n", "-".repeat(80));
        }
    }

    /// Allocate zerod pages for the `size` of the allocation at `addr`.
    pub fn alloc(&mut self, addr: u64, size: usize, metadata: Metadata)
        -> Result<(), MemoryError>
    {   // Calculate total page and needed allocation length.
        let page_count  = (size + self.arch.page_size - 1) / self.arch.page_size;
        let alloc_len   = (page_count * self.arch.page_size) as u64;

        // Duplicate zerod bytes into memory at address.
        self.memdup(addr, &vec![0; alloc_len as usize], metadata)
    }

    // Duplicate bytes into paged `Memory` with specified `Metadata`.
    pub fn memdup(&mut self, addr: u64, bytes: &[u8], metadata: Metadata)
        -> Result<(), MemoryError>
    {
        if bytes.is_empty() || bytes.len() > self.arch.max_mmap_size
        {
            return Err(MemoryError::Size(bytes.len()))
        }

        if !self.arch.validate_address(addr)
        {   // Propagate an error if the address isAm I doing s noncanonical.
            return Err(MemoryError::Noncanonical(addr))
        }
        // Calculate total page and needed allocation length.
        let page_count  = (bytes.len() + self.arch.page_size - 1) / self.arch.page_size;
        let alloc_len   = (page_count * self.arch.page_size) as u64;

        // The end address of the allocation.
        let end_addr    = addr.checked_add(alloc_len)
            .ok_or(MemoryError::OutOfBounds(addr, alloc_len as usize))?;

        if self.pages.overlaps(&(addr..end_addr))
        {   // Or propagate if the region overlaps a pre-existing one.
            return Err(MemoryError::Overlap(addr, end_addr))
        }

        let region = Page::new(RefCell::new(bytes.to_vec()), metadata);

        self.pages.insert(addr..end_addr, region);

        Ok(())
    }

    /// Find `Metadata` for an `addr`.
    pub fn get_metadata(&self, addr: u64)
        -> Option<&Metadata>
    {
        self.pages.get_key_value(&addr)
            .map(|(_, region)| &region.metadata)
    }

    /// Find regions that overlap with a given `range`.
    pub fn overlapping(&self, range: Range<u64>)
        -> impl Iterator<Item = (&Range<u64>, &Page)>
    {
        self.pages.overlapping(range)
    }

    /// Free a memory region and its associated range tracking.
    pub fn free(&mut self, addr: u64)
        -> Result<(), MemoryError>
    {   // Check if the range exists.
        if let Some((range, _)) = self.pages.get_key_value(&addr)
        {
            self.pages.remove(range.to_owned());

            return Ok(())
        }

        // Invalid region.
        Err(MemoryError::InvalidPage(addr))
    }

    /// Retrieves an `Iterator` of mapped memory meta data ranges in order.
    pub fn pages_iter(&self)
        -> impl Iterator<Item = (&Range<u64>, &Page)>
    {
        self.pages.iter()
    }

    /// Retrieves a `Vec` of bytes for the address of `addr` and `size`.
    pub fn read(&self, addr: u64, size: usize)
        -> Result<Vec<u8>, MemoryError>
    {
        let mut result          = Vec::with_capacity(size);
        let mut current_addr    = addr;
        let mut remaining       = size;

        while remaining > 0
        {
            let page_addr   = self.arch.page_align(current_addr & self.arch.page_mask())
                .ok_or(MemoryError::Noncanonical(current_addr))?;

            let offset      = (current_addr & (self.arch.page_size as u64 - 1)) as usize;

            // Try to get a reference to a page from the address.
            let Some(page) = &mut self.pages.get(&page_addr) else
            {
                return Err(MemoryError::InvalidPage(page_addr))
            };

            // Total amount read in this iteration.
            let read_size = std::cmp::min(remaining, self.arch.page_size - offset);

            // Extend the read result from the borrowed page data.
            result.extend_from_slice(&page.data.borrow()[offset..offset + read_size]);

            remaining       -= read_size;
            current_addr    += read_size as u64;
        }

        Ok(result)
    }

    /// Write `data` to address of `addr` in `Memory`.
    pub fn write(&mut self, addr: u64, data: &[u8])
        -> Result<(), MemoryError>
    {
        let page_size           = self.arch.page_size as u64;
        let mut current_addr    = addr;
        let mut remaining       = data.len();
        let mut data_offset     = 0;

        while remaining > 0
        {
            let page_addr   = self.arch.page_align(current_addr & !(page_size - 1))
                .ok_or(MemoryError::Noncanonical(current_addr))?;

            let offset      = (current_addr & (page_size - 1)) as usize;

            // Try to get a reference to a page from the address.
            let Some(page) = &mut self.pages.get(&page_addr) else
            {
                return Err(MemoryError::InvalidPage(page_addr))
            };

            // Get the total amount written in this iteration.
            let write_size  = std::cmp::min(remaining, page_size as usize - offset);

            // Write to the data.
            page.data.borrow_mut()[offset..offset + write_size]
                .copy_from_slice(&data[data_offset..data_offset + write_size]);

            remaining       -= write_size;
            current_addr    += write_size as u64;
            data_offset     += write_size;
        }

        Ok(())
    }
}
