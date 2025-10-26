use std::{ borrow::Borrow, collections::{HashMap, HashSet}, ops::Deref, path::Path };
use memory::RegionType;
use thiserror::Error;
use goblin::*;
use super::*;

mod plt
{
    use capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax};
    use derive_more::derive::Constructor;
    use keystone_engine::Keystone;
    use std::sync::LazyLock;
    use thiserror::Error;
    use super::*;

    #[derive(Error, Debug)] pub enum PltError
    {
        #[error("keystone failed with: {0}")]           Keystone(#[from] keystone_engine::KeystoneError),
        #[error("missed marker: [{0}]")]                Miss(&'static str),
        #[error("failed to map {0} to memory: {1}")]    Mapping(&'static str, memory::MemoryError),
    }

    /// Placeholder fields that are easily detectable.
    const PLACEHOLDER_GOT: u32      = 0x11223344;
    const PLACEHOLDER_INDEX: u32    = 0x55667788;
    const PLACEHOLDER_PLT0: u32     = 0x99AABBCC;

    #[derive(Debug, Constructor)] pub struct PltOffsets
    {
        pub got:    u64,
        pub index:  u64,
        pub plt0:   u64
    }

    /// The `PltTemplate` struct contains template
    /// stub code with the offsets for each placeholder.
    #[derive(Debug, Constructor)] pub struct PltTemplate
    {
        pub bytes:      Vec<u8>,
        pub offsets:    PltOffsets,
    }

    impl PltTemplate
    {   /// Map the template bytes of `PltTemplate` into `Memory` and patch the arguments.
        pub fn write(&self, memory: &mut Memory, target_addr: u64, plt0_addr: u64, index: u64)
            -> Result<(), PltError>
        {   // Directly memory map template stub.
            memory.write(target_addr, &self.bytes)
                .map_err(|e| PltError::Mapping("template bytes", e))?;

            // Calculate values.
            let got_addr    = target_addr as u32;
            let plt0_offset = (plt0_addr - target_addr) as i32;
            let index_value = index as u32;

            // Map each entries bytes to the target addr + template offset.
            [("GOT",    got_addr.to_le_bytes(),     target_addr + self.offsets.got),
             ("index",  index_value.to_le_bytes(),  target_addr + self.offsets.index),
             ("PLT0",   plt0_offset.to_le_bytes(),  target_addr + self.offsets.plt0)]
                .iter()
                .try_for_each(|&(name, bytes, addr)|
                    memory.write(addr, &bytes)
                        .map_err(|e| PltError::Mapping(name, e)))?;

            let cs = capstone::Capstone::new()
                .x86()
                .syntax(capstone::arch::x86::ArchSyntax::Intel)
                .detail(true)
                .mode(capstone::arch::x86::ArchMode::Mode64)
                .build().map_err(|_| PltError::Miss("wtf@x2"))?;

            let bytes = memory.read(target_addr, self.bytes.len())
                .map_err(|_| PltError::Miss("wtf"))?;

            for insn in cs.disasm_all(&bytes, target_addr).map_err(|_| PltError::Miss("Could not build the PLT stub"))?.iter()
            {
                println!("{:?}", insn);
            }

            Ok(())
        }

        pub fn len(&self)
            -> usize
        {
            self.bytes.len()
        }
    }

    // TODO: Implement a OnceLocked resource for determining which platform
    //       to generate the PLT stub for. e.x. OnceLock<PLTArchInfo> ==> { ... X86_64 ... }

    /// Lazily initialized PLT template code stub.
    /// This resource is used over multiple modules for generating and mapping PLT entries.
    pub static PLT_STUB: LazyLock<Result<PltTemplate, PltError>> = LazyLock::new(||
    {
        let ks = Keystone::new(keystone_engine::Arch::X86, keystone_engine::Mode::MODE_64)?;

        // Set keystone to intel syntax.
        ks.option(keystone_engine::OptionType::SYNTAX, keystone_engine::OptionValue::SYNTAX_INTEL)?;

        // For now, we only need a x86_64 stub template.
        // later, we can expand this with a OnceLocked resource, see above todo.
        let mut bytes = Vec::<u8>::new();

        let [got, index, plt0] = [
            ("jmp qword ptr [rip + {}]", PLACEHOLDER_GOT),
            ("push {}",                  PLACEHOLDER_INDEX),
            ("jmp {}",                   PLACEHOLDER_PLT0)].iter()
                .map(|&(insn_str, value)|
                {   // Bytes of instruction.
                    let result = ks.asm(insn_str.replace("{}", &format!("{:#x}", value)), 0)?.bytes;

                    // Get position of value.
                    let position = bytes.len() + result.len() - 4;

                    bytes.extend(result);

                    Ok::<_, PltError>(position as u64)
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .unwrap();

        // Construct our template PLT stub.
        Ok(PltTemplate::new(bytes, PltOffsets::new(got, index, plt0)))
    });
}

mod layout
{
    pub const DEFAULT_BASE_ADDR: u64 = 0x400000;
    pub const SHARED_BASE_ADDR: u64  = 0x7ffff7000000;
}

#[derive(Error, Debug)] pub enum LoaderError
{
    #[error("Module failed while: {0}")]        Module(#[from] module::ModuleError),
    #[error("Memory failed while: {0}")]        Memory(#[from] memory::MemoryError),
    #[error("PLT failed generating: {0}")]      Plt(#[from] plt::PltError),
    #[error("Unsupported feature: {0}")]        Feature(&'static str),
    #[error("Missing file data: {0}")]          Data(&'static str),
    #[error("missed symbol: {0}")]              Miss(String),
    #[error("invalid layout: {0:#x}, {0:#x}")]  Layout(u64, u64),
    #[error("invalid address, {0}: {1:#x}")]    Address(&'static str, u64),
}

pub struct Loader
{   /// Main program module.
    program: Module,

    /// Dependency tree of included shared libraries.
    includes: HashSet<Module>,

    /// Memory of the loaded program and its includes.
    pub memory: Memory,
}

impl Loader
{   /// Creates a new `Loader` instance from a path.
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
                        if let Some((_range, _metadata)) = memory.pages_iter()
                            .find(|(range, _)| range.start < seg_end && range.end > seg_start)
                        {
                            return Err(LoaderError::Layout(seg_start, seg_end))
                        }
                    }
                }

                // Validate address range.
                if start_addr < 0x10000
                {  // Protect low memory.
                    return Err(LoaderError::Address("address is too low in memory", start_addr))
                }

                Ok(())

            },
            // Uunsuported type for object.
            _ => Err(LoaderError::Feature("object type"))
        }
    }

    /// Loads an individiual `Module` into memory.
    fn load_segments(module: &Module, memory: &mut Memory)
        -> Result<(), LoaderError>
    {
        let arch        = module.arch()?;
        let module_path = module.path().to_string_lossy().to_string();
        let module_addr = module.base_addr();

        for phdr in module.filter_headers(|phdr|
            phdr.p_type == elf::program_header::PT_LOAD &&
            phdr.p_memsz > 0)?.iter()
        {
            let vaddr       = arch.align(module_addr + phdr.vm_range.start as u64);
            let end_vaddr   = arch.align(vaddr + phdr.vm_len() as u64 + arch.page_size as u64 - 1);
            let total_len  = (end_vaddr - vaddr) as usize;

            if !arch.validate_segment(vaddr, total_len, phdr.align)
            {   // Invalid segment range.
                return Err(LoaderError::Address("segment range is invalid", vaddr))
            }

            let region_type = match phdr.perms
            {
                p if p.contains(module::Perms::EXECUTE) => RegionType::Text,
                p if p.contains(module::Perms::WRITE)   => RegionType::Data,
                _                                       => RegionType::Other,
            };

            // Metadata for the memory page.
            let metadata = memory::Metadata::new(region_type, phdr.shdr_ranges.clone(), module_path.clone());

            // Get the raw file bytes from the module.
            let Some(file_bytes) = module.bytes().get(phdr.file_range.clone()) else
            {
                return Err(LoaderError::Data("missing file range for program header"))
            };

            // Initialize the page bytes.
            let mut page_bytes = vec![0; total_len];

            // Write the file data to the start of the page.
            page_bytes[..file_bytes.len()].copy_from_slice(file_bytes);

            // Duplicate our program headers into memory.
            memory.memdup(vaddr, &page_bytes, metadata)?;
        }

        Ok(())
    }

    /// Helper function to process symbols from a module
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
            if let Some(existing) = symbol_map.get(&symbol.name.to_string())
            {
                if existing.flags.contains(module::SymbolFlags::RESOLVED)
                {   // Skip if this symbol has a weaker definition than another.
                    continue;
                }
            }
            symbol_map.insert(symbol.name.to_string(), symbol);
        }

        // Process local symbols
        let locals = module.locals()?;
        for symbol in locals
        {   // Local symbols don't override globals
            if !symbol_map.contains_key(&symbol.name)
            {
                symbol_map.insert(symbol.name.to_string(), symbol);
            }
        }

        Ok(())
    }

    /// Process relocations for the main program.
    fn process_relocations(module: &Module, symbol_map: &HashMap<String, module::Symbol>, memory: &mut Memory)
        -> Result<(), LoaderError>
    {   // Get all the relocations for this module we need to solve for.
        let relocs  = module.relocs()?;

        // Generate a template PLT stub statically once.
        let plt = match plt::PLT_STUB.as_ref()
        {
            Ok(plt) => plt,
            Err(e) => return Err(LoaderError::Miss(e.to_string())),
        };

        // Get the module base address.
        let module_addr = module.base_addr();

        for reloc in relocs.iter()
        {
            let Some(sym_target) = symbol_map.get(&reloc.name) else
            {   // Early return if a symbol is missing from our map.
                return Err(LoaderError::Miss(reloc.name.clone()))
            };

            // Get the X86 relocation type that intersects with the mask.
            let x86_intersect = reloc.flags.clone().intersection(module::SymbolFlags::X86_MASK.clone());

            // Match the intersection to solve the relocation type.
            match x86_intersect
            {
                module::SymbolFlags::X86_PLT32 =>
                {   // Get the index for the PLT entry.
                    let Some(index) = reloc.value else
                    {   // Early return, malformed relocation entry information.
                        return Err(LoaderError::Data("PLT index missing"))
                    };

                    // Solve for the PLT0 address.
                    let plt0: u64 = plt.len() as u64 * index;

                    // Copy the PLT template stub into memory.
                    plt.write(memory, module_addr + reloc.addr, plt0, index)?;
                },
                module::SymbolFlags::X86_REL32 =>
                {   // PC-relative 32-bit relocation
                    let addend = reloc.value.unwrap_or(0);

                    let pc      = module_addr + reloc.addr + 4;
                    let offset  = (((sym_target.addr + addend) - pc) as i32).to_le_bytes();
                    memory.write(module_addr + reloc.addr, &offset)?;
                },

                _ => {}
            }
        }

        /*for reloc in relocs.iter()
        {
            let symbol_name = &reloc.name;

            if let Some(target) = symbol_map.get(symbol_name)
            {
                if !target.flags.contains(module::SymbolFlags::RESOLVED)
                {
                    return Err(LoaderError::Miss(symbol_name))
                }

                // Calculate the final symbol value for relocation
                let symbol_value = match reloc.flags
                {
                    f if f.contains(module::SymbolFlags::RELOC_PLT) =>
                    {   // For PLT entries, we'll create a PLT stub and return its address
                        let Some(index) = reloc.value else
                        {
                            return Err(LoaderError::Feature("missing reloc index"))
                        };

                        let plt0_addr: u64 = plt.len() as u64 * index;

                        plt.mmap(memory, reloc.addr, plt0_addr, index)?;

                        plt0_addr
                    },
                    //f if f.contains(module::SymbolFlags::RELOC_GOT) =>
                    //{   // For GOT entries, we'll create a GOT entry with the symbol's address
                    //    Self::create_got_entry(module, reloc, target, memory)?
                    //},
                    _ => target.addr // Direct symbol reference
                };

                // Get the relocation address.
                let reloc_addr = module.base_addr() + reloc.addr;

                // Get addend if present (RELA type).
                let addend = reloc.value.unwrap_or(0);

                // Extract x86-specific flags to determine the relocation type.
                let x86_type = reloc.flags.intersection(module::SymbolFlags::X86_MASK);

                match x86_type
                {


                    module::SymbolFlags::X86_GOTPC32 =>
                    {   // GOT PC-relative relocation
                        let pc          = reloc_addr + 4;
                    //    let got_entry   = Self::create_got_entry(module, reloc, target, memory)?;
                    //    let offset      = (got_entry - pc) as i32;
                    //    memory.mmap(&offset.to_le_bytes(), reloc_addr)?;
                    },

                    module::SymbolFlags::X86_PLT32 =>
                    {   // PLT PC-relative relocation
                        let pc          = reloc_addr + 4;
                    //    let plt_entry   = Self::create_plt_entry(module, reloc, target, memory)?;
                    //    let offset      = (plt_entry - pc) as i32;
                    //    memory.mmap(&offset.to_le_bytes(), reloc_addr)?;
                    },
                    _ => return Err(LoaderError::Feature("relocation type"))
                }
            }
            else
            {
                return Err(LoaderError::Miss(symbol_name))
            }
        }*/
        Ok(())
    }

    fn load_symbols(program: &Module, modules: &HashSet<Module>, memory: &mut Memory)
        -> Result<(), LoaderError>
    {
        // Create symbol resolution maps
        let mut symbol_map: HashMap<String, module::Symbol> = HashMap::new();
        let mut processed_modules: HashSet<&Module>         = HashSet::new();

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

        // Process and load the symbols from each module.
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
