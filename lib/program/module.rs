use std::{ borrow::Borrow, cmp::Ordering,
    collections::HashSet, hash::{ Hash, Hasher },
    ops::{BitXor, Range}, path::{ Path, PathBuf }, sync::LazyLock
};

use derive_more::AsRef;
use super::arch::{ Arch, X86_64 };
use thiserror::Error;
use goblin::*;

pub type IncludePaths = HashSet<PathBuf>;

#[derive(Error, Debug)] pub enum ModuleError
{
    #[error("failed to parse object file")]     Goblin(#[from] goblin::error::Error),
    #[error("failed to open file from path")]   Io(#[from] std::io::Error),
    #[error("object format is unsupported")]    Unsupported,
    #[error("invalid file path")]               FilePath,
    #[error("failed to locate an include")]     Missing,
    #[error("nonconnonical path")]              Noncononical,
    #[error("incompatible identities")]         Incompatible,
}

/// Recursively process `ld.so.conf` configurations.
fn process_conf_content(content: &str, paths: &mut IncludePaths)
{
    for line in content.lines().map(str::trim)
        .filter(|l| !(l.is_empty() || l.starts_with('#')))
    {
        if let Some(pattern) = line.strip_prefix("include").map(str::trim)
        {
            if let Ok(includes) = glob::glob(pattern)
            {
                for path in includes.filter_map(Result::ok)
                {
                    if let Ok(content) = std::fs::read_to_string(path)
                    {
                        process_conf_content(&content, paths);
                    }
                }
            }
            continue;
        }

        let path = PathBuf::from(line);

        if path.is_absolute() && path.exists()
        {
            if let Ok(canonical) = path.canonicalize()
            {
                paths.insert(canonical);
            }
        }
    }
}

/// Process system library paths and parse `ld.so.conf` configs.
static INCLUDE_PATHS: LazyLock<IncludePaths> = LazyLock::new(||
{   // Default include paths.
    let mut paths = HashSet::from([
            "/lib",
            "/usr/lib",
            "/lib64",
            "/usr/lib64",
            "/usr/local/lib",
            "/usr/local/lib64"
          ]).iter()
            .map(PathBuf::from)
            .filter(|path| path.exists())
            .collect();

    // Get all .conf files from ld.so.conf.d
    if let Ok(conf_entries) = glob::glob("/etc/ld.so.conf.d/*.conf")
    {   // Process each .conf found.
        for entry in conf_entries.filter_map(Result::ok)
        {
            if let Ok(content) = std::fs::read_to_string(&entry)
            {
                process_conf_content(&content, &mut paths);
            }
        }
    }

    if let Ok(content) = std::fs::read_to_string("/etc/ld.so.conf")
    {   // Process the main ld.so.conf file.
        process_conf_content(&content, &mut paths);
    }

    paths
});

bitflags::bitflags!
{
    #[derive(Debug, Default, Clone)] pub struct SymbolFlags: u8
    {   // Symbol Type (bits 1-0): 00=Variable/Data
        //                         01=Function
        //                         10=Indirect Function
        //                         11=Reserved for future use
        const TYPE_MASK    = 0b0000_0011;
        const TYPE_VAR     = 0b0000_0000;
        const TYPE_FUNC    = 0b0000_0001;
        const TYPE_IFUNC   = 0b0000_0010;

        // Resolution State (bit 2): 0=Undefined symbol
        //                          1=Resolved/defined symbol
        const RESOLVED     = 0b0000_0100;

        // Relocation Category (bits 4-3): 00=Direct (no special handling)
        //                                 01=PLT entry required
        //                                 10=GOT entry required
        //                                 11=Requires relocation processing
        const RELOC_MASK   = 0b0001_1000;
        const RELOC_DIRECT = 0b0000_0000;
        const RELOC_PLT    = 0b0000_1000;
        const RELOC_GOT    = 0b0001_0000;
        const RELOC_REL    = 0b0001_1000;

        // X86 Relocation Type (bits 7-5): 000=No specific type
        //                                 001=PC-relative 32-bit
        //                                 010=Absolute 32-bit
        //                                 011=Absolute 64-bit
        //                                 100=GOT PC-relative 32-bit
        //                                 101=GOT offset 64-bit
        //                                 110=PLT 32-bit
        //                                 111=Special handling required
        const X86_MASK     = 0b1110_0000;
        const X86_REL32    = 0b0010_0000;
        const X86_ABS32    = 0b0100_0000;
        const X86_ABS64    = 0b0110_0000;
        const X86_GOTPC32  = 0b1000_0000;
        const X86_GOTOFF64 = 0b1010_0000;
        const X86_PLT32    = 0b1100_0000;
        const X86_SPECIAL  = 0b1110_0000;
    }
}

/// The `Symbol` struct contains information about a found symbol within a `Module`.
#[derive(Debug, Default)] pub struct Symbol
{
    name:    String,
    flags:   SymbolFlags,
    addr:    u64,
    value:   Option<u64>,
}

impl Hash for Symbol
{
    fn hash<H: Hasher>(&self, state: &mut H)
    {   // Hash the name of the symbol.
        self.name.hash(state);

        // Hash the type mask for the symbol.
        (self.flags.bits() & SymbolFlags::TYPE_MASK.bits()).hash(state);
    }
}

impl Eq for Symbol {}
impl PartialEq for Symbol
{
    fn eq(&self, other: &Self)
        -> bool
    {
        self.name == other.name
    }
}

impl Ord for Symbol
{
    fn cmp(&self, other: &Self)
        -> Ordering
    {
        self.name.cmp(&other.name)
    }
}

impl PartialOrd for Symbol
{
    fn partial_cmp(&self, other: &Self)
        -> Option<Ordering>
    {
        Some(self.cmp(other))
    }
}

impl Symbol
{
    /// Creates a new symbol with basic information from an ELF symbol entry
    pub fn new(name: &str, addr: u64, value: Option<u64>, base_flags: SymbolFlags, sym: &elf::Sym) 
        -> Self 
    {
        // Start with base flags that indicate relocation type (PLT/REL/RELA)
        let mut flags = base_flags;

        // Add symbol type information (bits 1-0)
        flags |= match sym.st_type()
        {
            elf::sym::STT_FUNC      => SymbolFlags::TYPE_FUNC,
            elf::sym::STT_GNU_IFUNC => SymbolFlags::TYPE_IFUNC,
            _                       => SymbolFlags::TYPE_VAR
        };

        // Set resolution state (bit 2)
        if sym.st_shndx != (elf::section_header::SHN_UNDEF as usize)
        {
            flags |= SymbolFlags::RESOLVED;
        }

        // Create the symbol, relocation-specific flags will be added later
        Self
        {
            name: name.to_string(),
            flags,
            addr,
            value,
        }
    }

    /// Adds x86 relocation flags based on the relocation entry type
    pub fn set_x86_reloc_flags(&mut self, reloc: &elf::Reloc) -> &mut Self
    {   // Clear existing x86 relocation flags
        self.flags &= !SymbolFlags::X86_MASK;

        // Set new flags based on relocation type
        let x86_flags = match reloc.r_type
        {   // PC-relative relocations.
            elf::reloc::R_X86_64_PC32 | elf::reloc::R_X86_64_PLT32 =>
            {
                if self.flags.contains(SymbolFlags::RELOC_PLT)
                {
                    SymbolFlags::X86_PLT32
                }
                else
                {
                    SymbolFlags::X86_REL32
                }
            },

            // Absolute relocations.
            elf::reloc::R_X86_64_64                             => SymbolFlags::X86_ABS64,
            elf::reloc::R_X86_64_32 | elf::reloc::R_X86_64_32S  => SymbolFlags::X86_ABS32,

            // GOT-related relocations.
            elf::reloc::R_X86_64_GOTPC32 | elf::reloc::R_X86_64_GOTPCREL    => SymbolFlags::X86_GOTPC32,
            elf::reloc::R_X86_64_GOTOFF64                                   => SymbolFlags::X86_GOTOFF64,
            _                                                               => SymbolFlags::X86_SPECIAL
        };

        self.flags |= x86_flags;
        self
    }

    pub fn name(&self)
        -> &str
    {
        &self.name
    }

    pub fn addr(&self)
        -> u64
    {
        self.addr
    }

    pub fn value(&self)
        -> Option<u64>
    {
        self.value
    }

    pub fn flags(&self)
        -> SymbolFlags
    {
        self.flags.clone()
    }
}

/// The `Module` struct contains information about a loaded `Object` file.
#[derive(Debug, AsRef)] pub struct Module
{   /// Raw bytes of `Module`.
    bytes: Vec<u8>,

    /// Base address of `Module`.
    base_addr: u64,

    /// Path of the `Module`.
    #[as_ref] path: PathBuf
}

impl Hash for Module
{
    fn hash<H: Hasher>(&self, state: &mut H)
    {
        self.path.hash(state)
    }
}

impl Eq for Module {}
impl PartialEq for Module
{
    fn eq(&self, other: &Self)
        -> bool
    {
        self.path == other.path
    }
}

impl Ord for Module
{
    fn cmp(&self, other: &Self)
        -> Ordering
    {
        self.path.cmp(&other.path)
    }
}

impl PartialOrd for Module
{
    fn partial_cmp(&self, other: &Self)
        -> Option<Ordering>
    {
        Some(self.cmp(other))
    }
}

impl Borrow<Path> for Module
{
    fn borrow(&self)
        -> &Path
    {
        &self.path
    }
}

impl Module
{   // Retrieves all the include paths for dependencies.
    pub fn include_paths(&self)
        -> Result<IncludePaths, ModuleError>
    {
        let mut paths   = IncludePaths::new();

        match self.object()?
        {
            Object::Elf(elf) =>
            {
                for dynamic in elf.dynamic.iter()
                {
                    for dy in dynamic.dyns.iter()
                    {
                        if dy.d_tag != elf::dynamic::DT_RPATH || dy.d_tag != elf::dynamic::DT_RUNPATH
                        {   // Ignore any entries that are not search path related.
                            continue;
                        }

                        let Some(path) = elf.dynstrtab.get_at(dy.d_val as usize) else
                        {   // Ignore any nameless entries.
                            continue;
                        };

                        paths.insert(path.into());

                    }
                }
            },
            // Unsupported `Module` format type.
            _ => return Err(ModuleError::Unsupported)
        }
        Ok(paths)
    }

    /// Retrieves a HashSet of included objects by `PathBuf` for `Module`.
    pub fn includes(&self)
        -> Result<IncludePaths, ModuleError>
    {
        let mut resolved        = HashSet::new();

        // Default search paths and ones defined in ld.conf.
        let mut search_paths    = INCLUDE_PATHS.clone();

        // Extend by paths included in DT_RPATH and DT_RUNPATH.
        search_paths.extend(self.include_paths()?);

        fn resolve_includes(module: &Module, search_paths: &IncludePaths, resolved: &mut IncludePaths)
            -> Result<(), ModuleError>
        {   // Skip if already resolved.
            if !resolved.insert(module.path())
            {
                return Ok(())
            }

            match module.object()?
            {
                Object::Elf(elf) =>
                {   // Resolve the interpreter (ld) path first.
                    if let Some(ld_path) = elf.interpreter.map(PathBuf::from)
                    {
                        if ld_path.exists()
                        {
                            let Ok(canonical_path) = ld_path.canonicalize() else
                            {
                                return Err(ModuleError::Noncononical)
                            };

                            let module = Module::new(&canonical_path, 0)?;
                            resolve_includes(&module, search_paths, resolved)?;
                        }
                    }

                    // Resolve any other shared objects.
                    for dynamic in elf.dynamic.iter()
                    {
                        for dy in dynamic.dyns.iter()
                        {
                            if  dy.d_tag != elf::dynamic::DT_NEEDED
                            {   // Ignore any entries without the tag of DT_NEEDED.
                                continue;
                            }

                            let Some(so_name) = elf.dynstrtab.get_at(dy.d_val as usize) else
                            {   // Ignore any nameless entries.
                                continue;
                            };

                            for (i, search_path) in search_paths.iter().enumerate()
                            {
                                let mod_path = search_path.join(so_name);

                                if mod_path.exists()
                                {
                                    let Ok(canonical_path) = mod_path.canonicalize() else
                                    {
                                        return Err(ModuleError::Noncononical)
                                    };

                                    let module = Module::new(&canonical_path, 0)?;

                                    resolve_includes(&module, search_paths, resolved)?;
                                    break;
                                }

                                if i == search_paths.len()
                                {   // We tried all the search paths and we're still missing a
                                    // shared object,we can't proceed without it.
                                    return Err(ModuleError::Missing)
                                }
                            }
                        }
                    }
                    Ok(())
                },
                // Unsupported `Module` format type.
                _ => Err(ModuleError::Unsupported)
            }
        }

        // Recursively resolve all the includes for each `Module` including this one.
        resolve_includes(self, &search_paths, &mut resolved)?;
        Ok(resolved)
    }

    /// Collects symbols from a symbol table using a predicate and string table.
    fn filter_symbols<F>(pred: F, symtab: &elf::Symtab, strtab: &strtab::Strtab, base_addr: u64, flags: SymbolFlags)
        -> HashSet<Symbol>
        where F: Fn(&elf::Sym) -> bool
    {
        let mut symbols = HashSet::new();

        for sym in symtab.iter()
        {
            if !pred(&sym)
            {   // Apply the predicate first.
                continue;
            }

            let Some(sym_name) = strtab.get_at(sym.st_name).filter(|s| !s.is_empty()) else
            {   // Skip nameless entries.
                continue;
            };

            // Get the virtual address of the entry
            let sym_addr = sym.st_value + base_addr;

            // Collect information about the symbol
            let sym_info = Symbol::new(sym_name, sym_addr, Some(sym.st_size), flags.clone(), &sym);

            // Track the symbols info
            symbols.insert(sym_info);
        }
        symbols
    }

    /// Process relocations from an ELF file based on a predicate function
    fn filter_relocs(relocs: &elf::RelocSection, dynsyms: &elf::Symtab, dynstrtab: &strtab::Strtab, base_flags: SymbolFlags)
        -> HashSet<Symbol>
    {
        let mut symbols = HashSet::new();

        for rel in relocs.iter()
        {   // Get corresponding symbol from dynamic symbol table
            let Some(sym) = dynsyms.get(rel.r_sym) else
            {
                continue;
            };

            // Get symbol name, skip if empty
            let Some(sym_name) = dynstrtab.get_at(sym.st_name).filter(|s| !s.is_empty()) else
            {
                continue;
            };

            // Create symbol with base information
            let mut sym_info = Symbol::new(sym_name, rel.r_offset, rel.r_addend.map(|x| x as u64), base_flags.clone(), &sym);

            // Add architecture-specific relocation information
            sym_info.set_x86_reloc_flags(&rel);

            // Add to collection
            symbols.insert(sym_info);
        }

        symbols
    }

    /// Retrieves all globally visible symbols of this `Module`.
    pub fn globals(&self)
        -> Result<HashSet<Symbol>, ModuleError>
    {
        match self.object()?
        {
            Object::Elf(elf) =>
            {
                let globals = Self::filter_symbols(
                    |sym| sym.st_bind() == elf::sym::STB_GLOBAL ||
                          sym.st_bind() == elf::sym::STB_WEAK,
                    &elf.dynsyms,
                    &elf.dynstrtab,
                    self.base_addr(),
                    SymbolFlags::empty());
                Ok(globals)
            },
            // Unsupported `Module` format type.
            _ => Err(ModuleError::Unsupported),
        }
    }

    /// Retrieves all locally defined symbols of this `Module`.
    pub fn locals(&self)
        -> Result<HashSet<Symbol>, ModuleError>
    {
        match self.object()?
        {
            Object::Elf(elf) =>
            {
                let locals = Self::filter_symbols(
                    |sym| sym.st_bind() == elf::sym::STB_LOCAL,
                    &elf.syms,
                    &elf.strtab,
                    self.base_addr(),
                    SymbolFlags::empty());
                Ok(locals)
            },
            // Unsupported `Module` format type.
            _ => Err(ModuleError::Unsupported),
        }
    }

    /// Retrieves the relocations of this `Module`.
    pub fn relocs(&self)
        -> Result<HashSet<Symbol>, ModuleError>
    {
        let mut rels = HashSet::new();

        match self.object()?
        {
            Object::Elf(elf) =>
            {
                rels.extend(Self::filter_relocs(
                    &elf.pltrelocs,
                    &elf.dynsyms,
                    &elf.dynstrtab,
                    SymbolFlags::RELOC_PLT));

                rels.extend(Self::filter_relocs(
                    &elf.dynrels,
                    &elf.dynsyms,
                    &elf.dynstrtab,
                    SymbolFlags::RELOC_REL));

                rels.extend(Self::filter_relocs(
                    &elf.dynrelas,
                    &elf.dynsyms,
                    &elf.dynstrtab,
                    SymbolFlags::RELOC_REL));
            },
            // Unsupported `Module` format type.
            _ => return Err(ModuleError::Unsupported)
        }
        Ok(rels)
    }

    /// Checks the compatibility of this object against another.
    pub fn compatible(&self, module: &Module)
        -> Result<(), ModuleError>
    {
        match &self.object()?
        {
            Object::Elf(elf) =>
            {
                match module.object()?
                {
                    Object::Elf(other_elf) =>
                    {   // Check e_machine compatibility.
                        if elf.header.e_machine != other_elf.header.e_machine
                        {
                            return Err(ModuleError::Incompatible)
                        }

                        // Elf identification range to compare for strict compatibility.
                        const EI_RANGE: Range<usize> = elf::header::EI_CLASS..elf::header::EI_OSABI;

                        for (i, ident) in elf.header.e_ident[EI_RANGE].iter().enumerate()
                        {
                            let other = other_elf.header.e_ident[EI_RANGE.start + i];

                            if other != *ident
                            {
                                return Err(ModuleError::Incompatible)
                            }
                        }

                        let abi         = elf.header.e_ident[elf::header::EI_ABIVERSION];
                        let other_abi   = other_elf.header.e_ident[elf::header::EI_ABIVERSION];

                        // Loosely compare ABI compatibility.
                        match (abi, other_abi)
                        {   // Same types.
                            (a, b) if a == b => {},
                            // None/SYSV and Linux are considered compatible.
                            (elf::header::ELFOSABI_NONE, elf::header::ELFOSABI_LINUX) |
                            (elf::header::ELFOSABI_LINUX, elf::header::ELFOSABI_NONE) => {},
                            // Unsupported combination of ABI versions.
                            _ => return Err(ModuleError::Incompatible)
                        }

                        Ok(())
                    },
                    // Differing object file types.
                    _ => Err(ModuleError::Incompatible)
                }
            },
            // Unsupported `Module` format type.
            _ => Err(ModuleError::Unsupported)
        }
    }

    /// Calculates the total length of memory this `Module` consumes when being mapped.
    pub fn len(&self)
        -> Result<u64, ModuleError>
    {
        match self.object()?
        {
            Object::Elf(elf) =>
            {
                let mut max_size    = 0;
                let mut max_align   = 0x1000;

                for phdr in elf.program_headers.iter()
                {
                    if phdr.p_type == elf::program_header::PT_LOAD
                    {   // Calculate the end of this header.
                        let seg_end = phdr.p_vaddr + phdr.p_memsz;
                        max_size    = max_size.max(seg_end);

                        // Track the maximum alignment.
                        if phdr.p_align > 0
                        {
                            max_align = max_align.max(phdr.p_align);
                        }
                    }
                }

                // Round up to nearest alignment boundary and add safety padding.
                let aligned_size = (max_size + max_align - 1) & !(max_align - 1);

                // Add 2MB minimum spacing between modules for safety,
                // This matches memory mapping alignment found in glibc.
                Ok(aligned_size + 0x200000)
            },
            _ => Err(ModuleError::Unsupported)
        }
    }

    /// Calculates length of program headers and determines if the module is empty.
    // This is really just here to silence clippy errors.
    pub fn is_empty(&self)
        -> Result<bool, ModuleError>
    {
        Ok(self.len()? == 0)
    }

    /// Retrieves the architecture of the `Module`.
    pub fn arch(&self)
        -> Result<&Arch, ModuleError>
    {
        match self.object()?
        {
            Object::Elf(elf) =>
            {   // TODO: Put more effort into resolving architectural information.
                match elf.header.e_machine
                {
                    elf::header::EM_X86_64  => Ok(&X86_64),
                    _                       => Err(ModuleError::Unsupported),
                }
            },
            // Unsupported `Module` format type.
            _ => Err(ModuleError::Unsupported),
        }
    }

    // Retrieves ref to the bytes of the `Module`.
    pub fn bytes(&self)
        -> &[u8]
    {
        &self.bytes
    }

    /// Retrieves the `Module` base address.
    pub fn base_addr(&self)
        -> u64
    {
        self.base_addr
    }

    /// Retrieves the `Module` path.
    pub fn path(&self)
        -> PathBuf
    {
        self.path.clone()
    }

    /// Retrieves the `Module` object type.
    pub fn object(&self)
        -> Result<Object, ModuleError>
    {
        Ok(Object::parse(&self.bytes)?)
    }

    pub fn new(path: &impl AsRef<Path>, base_addr: u64)
        -> Result<Module, ModuleError>
    {
        let bytes   = std::fs::read(path)?;
        let path    = path.as_ref().to_path_buf();

        Ok(Self
        {
            bytes,
            base_addr,
            path
        })
    }
}
