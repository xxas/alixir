use std::{ collections::{HashMap, HashSet}, path::Path };
use rangemap::RangeMap;
use thiserror::Error;
use goblin::*;
use super::*;

#[derive(Error, Debug)] pub enum LoaderError
{
    #[error("{0}")]                                 Module(#[from] module::ModuleError),
    #[error(":{0}")]                                Memory(#[from] memory::MemoryError),
    #[error("failed to map symbol information")]    Symbols,
    #[error("address of {0:#x} is out of range")]   OutOfRange(u64),
    #[error("object format is unsupported")]        Unsupported,
}

mod layout
{
    pub const DEFAULT_BASE_ADDR: u64 = 0x400000;
    pub const SHARED_BASE_ADDR: u64  = 0x7ffff7000000;
}

/// ELF Program Loader
/// Responsible for:
/// - Loading main program and dependencies.
/// - Managing virtual address space layout.
/// - Handling relocations and dynamic linking.
pub struct Loader
{   /// Main program module.
    program: Module,

    /// Dependency tree of included shared libraries.
    includes: HashSet<Module>,

    /// Memory of the loaded program and its includes.
    memory: Memory,
}

impl Loader
{
    /// Creates a new `Loader` instance from a path.
    pub fn from_path(path: impl AsRef<Path>, base_addr: u64)
        -> Result<Self, LoaderError>
    {   // Default base for executables (Linux standard).
        let program_base_addr = if base_addr < 0x400000
        {
            layout::DEFAULT_BASE_ADDR
        }
        else
        {
            base_addr
        };

        let program = Module::new(&path, program_base_addr)?;

        // Shared object base addresses start after the program.
        let mut so_base_addr = layout::SHARED_BASE_ADDR;

        let includes: HashSet<Module> = program.includes()?.iter()
            .map(|so_path|
            {   // Load the dependency as a module.
                let result = Module::new(so_path, so_base_addr);

                match &result
                {
                    Ok(module)  => so_base_addr += module.len()?,
                    _           => so_base_addr += 0x200000,
                };

                result
            })
            .collect::<Result<_, _>>()?;

        for include in includes.iter()
        {   // Validate program-object compatibility.
            program.compatible(include)?
        }

        // Initialize the memory for our program.
        let memory = Memory::new(program.arch()?.clone());

        Ok(Self
        {
            program,
            includes,
            memory
        })
    }

    /// Validates the layout of a `Module`.
    fn validate_layout(module: &Module, memory: &Memory)
        -> Result<(), LoaderError>
    {
        match module.object()?
        {
            Object::Elf(elf) =>
            {   // Track the address range of the `Module`.
                let mut start_addr  = u64::MAX;
                let mut end_addr    = 0u64;

                for phdr in elf.program_headers.iter()
                {
                    if phdr.p_type != elf::program_header::PT_LOAD
                    {
                        let seg_start   = module.base_addr() + phdr.p_vaddr;
                        let seg_end     = seg_start + phdr.p_memsz;

                        // Update the address range for the `Module`.
                        start_addr  = start_addr.min(seg_start);
                        end_addr    = end_addr.max(seg_end);

                        // Check against mapped ranges.
                        if let Some((_range, _metadata)) = memory.mapped_ranges()
                            .find(|(range, _)| range.start < seg_end && range.end > seg_start)
                        {
                            return Err(memory::MemoryError::Overlapping(seg_start, seg_end).into())
                        }
                    }
                }

                // Validate address range.
                if start_addr < 0x10000
                {  // Protect low memory.
                    return Err(LoaderError::OutOfRange(start_addr))
                }

                Ok(())

            },
            _ => Err(LoaderError::Unsupported)
        }
    }

    /// Loads an individiual `Module` into memory.
    fn load_segments(module: &Module, memory: &mut Memory)
        -> Result<(), LoaderError>
    {
        match module.object()?
        {
            Object::Elf(elf) =>
            {
                for phdr in elf.program_headers.iter()
                {   // Ignore any non-loadable headers.
                    if phdr.p_type != elf::program_header::PT_LOAD
                    {
                        continue;
                    }

                    // Calculate addresses.
                    let vaddr           = module.base_addr() + phdr.p_vaddr;
                    let page_size       = module.arch()?.page_size as u64;
                    let aligned_vaddr   = vaddr & !(page_size - 1);
                    let end_vaddr       = (vaddr + phdr.p_memsz + page_size - 1) & !(page_size - 1);
                    let total_size      = (end_vaddr - aligned_vaddr) as usize;

                    // Create metadata for the segment.
                    let metadata = memory::MemoryMetadata
                    {
                        module:         Some(module.path().to_string_lossy().into_owned()),
                        name:           Some(format!("{}:{:#x}", module.path().display(), vaddr)),
                        file_offset:    Some(phdr.p_offset),
                        file_size:      Some(phdr.p_filesz),
                        region_type:    match phdr.p_flags
                            {
                                f if f & elf::program_header::PF_X != 0 => memory::RegionType::Text,
                                f if f & elf::program_header::PF_W != 0 => memory::RegionType::Data,
                                _                                       => memory::RegionType::Other,
                            },
                    };

                    // Convert ELF flags to memory permissions.
                    let perms = memory::PagePerms::from_bits_truncate(
                        ((phdr.p_flags & elf::program_header::PF_R != 0) as u8)      |
                        ((phdr.p_flags & elf::program_header::PF_W != 0) as u8) << 1 |
                        ((phdr.p_flags & elf::program_header::PF_X != 0) as u8) << 2
                    );

                    // allocate a new page for the total size of the header.
                    memory.allocate(aligned_vaddr, total_size, perms, metadata)?;

                    if phdr.p_filesz > 0
                    {   // Copy header bytes into memory.
                        let mut bytes = vec![0u8; total_size];

                        let offset_in_page  = (vaddr & (page_size - 1)) as usize;
                        let file_data       = &module.bytes()[phdr.p_offset as usize..(phdr.p_offset + phdr.p_filesz) as usize];

                        bytes[offset_in_page..(offset_in_page + file_data.len())]
                            .copy_from_slice(file_data);

                        // Copy the header slice to the address.
                        memory.copy(&bytes, aligned_vaddr)?;
                    }
                }
                Ok(())
            },
            _ => Err(LoaderError::Unsupported)
        }
    }

    // Helper function to process symbols from a module
    fn process_module_symbols<'a>(module: &'a Module, symbol_map: &mut HashMap<String, module::Symbol>, processed: &mut HashSet<&'a Module>)
        -> Result<(), LoaderError>
    {   // Skip if already processed
        if !processed.insert(module)
        {
            return Ok(());
        }

        // Process global symbols first.
        let globals = module.globals()?;
        for symbol in globals
        {
            // Only insert if undefined or has higher precedence
            if let Some(existing) = symbol_map.get(&symbol.name().to_string())
            {
                if existing.flags().contains(module::SymbolFlags::RESOLVED)
                {   // Skip if this symbol has a weaker definition than another.
                    continue;
                }
            }
            symbol_map.insert(symbol.name().to_string(), symbol);
        }

        // Process local symbols
        let locals = module.locals()?;
        for symbol in locals
        {   // Local symbols don't override globals
            if !symbol_map.contains_key(symbol.name())
            {
                symbol_map.insert(symbol.name().to_string(), symbol);
            }
        }

        Ok(())
    }

    /// Process relocations for the main program.
    fn process_relocations(module: &Module, symbol_map: &HashMap<String, module::Symbol>, memory: &mut Memory)
        -> Result<(), LoaderError>
    {
        let relocs = module.relocs()?;

        for reloc in relocs.iter()
        {
            let symbol_name = reloc.name();

            // Find the target symbol
            if let Some(target) = symbol_map.get(symbol_name)
            {
                if target.flags().contains(module::SymbolFlags::RESOLVED)
                {
                    return Err(LoaderError::Symbols)
                }


            }
            else
            {
                return Err(LoaderError::Symbols)
            }
        }
        Ok(())
    }

    fn load_symbols(program: &Module, modules: &HashSet<Module>, memory: &mut Memory)
        -> Result<(), LoaderError>
    {
        // Create symbol resolution maps
        let mut symbol_map: HashMap<String, module::Symbol> = HashMap::new();
        let mut processed_modules: HashSet<&Module> = HashSet::new();

        // First process the main program's symbols
        Self::process_module_symbols(program, &mut symbol_map, &mut processed_modules)?;

        // Then process symbols from all shared objects
        for module in modules.iter()
        {
            Self::process_module_symbols(module, &mut symbol_map, &mut processed_modules)?;
        }

        // Process relocations for the main program
        Self::process_relocations(program, &symbol_map, memory)?;

        // Process relocations for all shared objects
        for module in modules.iter()
        {
            Self::process_relocations(module, &symbol_map, memory)?;
        }

        Ok(())
    }

    /// Main loading function that processes the entire program.
    pub fn load(&mut self)
        -> Result<(), LoaderError>
    {   // Validate the layout of the program.
        Self::validate_layout(&self.program, &self.memory)?;

        // Load the program into memory.
        Self::load_segments(&self.program, &mut self.memory)?;

        // Load included shared module segments.
        for next in self.includes.iter()
        {
            Self::validate_layout(next, &self.memory)?;
            Self::load_segments(next, &mut self.memory)?;
        }

        // Load the 
        Self::load_symbols(&self.program, &self.includes, &mut self.memory)?;

        Ok(())
    }

    /// Returns reference to the main program module
    pub fn program(&self)
        -> &Module
    {
        &self.program
    }

    /// Returns reference to the dependency set
    pub fn includes(&self)
        -> &HashSet<Module>
    {
        &self.includes
    }
}
