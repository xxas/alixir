use crate::{ il::{ BasicBlock, BlockTerminator, Expression, Function,
            Instruction, Intrinsic, Operation, Scalar },
    program::{memory::{self, Memory}, module::{self, Module}, Arch}
};

use std::{collections::{ HashMap, HashSet }, ops::RangeBounds, sync::Arc };
use arch::x86::{ArchSyntax, X86Operand, X86OperandType};
use capstone::prelude::*;
use thiserror::Error;

/// Errors that can occur during binary translation
#[derive(Error, Debug)] pub enum TranslationError
{
    #[error("capstone failed")]                                         Capstone(#[from] capstone::Error),
    #[error("memory manager failed")]                                   Memory(#[from] memory::MemoryError),
    #[error("module parsing failed")]                                   Module(#[from] module::ModuleError),
    #[error("failed to parse instruction")]                             InstructionParsing,
    #[error("unsupported instruction: {0}")]                            UnsupportedInstruction(String),

}

/// Binary translator for converting machine code to IL
/// 
/// Following principles from academic literature on binary analysis:
/// - Uses Single Static Assignment (SSA) form [1]
/// - Implements value-set analysis for indirect jumps [2]
/// - Handles delayed slots and instruction semantics [3]
/// 
/// [1] Cytron et al. "Efficiently Computing Static Single Assignment Form"
/// [2] Balakrishnan & Reps "WYSINWYX: What You See Is Not What You eXecute"
/// [3] Schwarz et al. "Disassembly of Executable Code Revisited"
#[derive(Debug)] pub struct BinaryTranslator<'a>
{   /// Capstone disassembly engine
    cs:             Capstone,

    /// Target architecture information
    arch:           Arch,

    /// Memory containing program code and data
    memory:         &'a Memory,

    /// Cache of translated functions
    functions:      HashMap<u64, Function>,
}

impl<'a> BinaryTranslator<'a>
{   /// Creates a new binary translator
    pub fn new(module: &Module, memory: &'a Memory)
        -> Result<Self, TranslationError>
    {   // Initialize Capstone for target architecture.
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(ArchSyntax::Intel)
            .detail(true)
            .build()?;
&
        Ok(Self
        {
            cs,
            arch: module.arch()?,
            memory,
            functions: HashMap::new(),
        })
    }

    fn translate_operand(&self, op: &X86Operand)
        -> Result<Expression, TranslationError>
    {
        match op.op_type
        {
            X86OperandType::Reg(reg_id) =>
            {   // Get the registers name.
                let reg_name = self.cs.reg_name(reg_id)
                    .ok_or(TranslationError::InstructionParsing)?;
                // Get the bitness of the register.
                let bitness = Self::get_reg_bitness(reg_id.0);

                // Produce a scalar from the register information.
                Ok(Expression::Scalar(Scalar::new(reg_name, bitness)))
            }
            X86OperandType::Imm(immediate) =>
            {   // Get the bitness from the operands width.
                let bitness = (op.size * 8) as u16;

                // Produce a scalar from the immediate values information.
                Ok(Expression::Constant(Scalar::new(immediate.to_string(), bitness)))
            },
            X86OperandType::Mem(mem) =>
            {
                

            },
            // We can't parse this operand, it's invalid.
            X86OperandType::Invalid => Err(TranslationError::InstructionParsing)
        }
    }

    /// Retrieves the bitness of a register.
    fn get_reg_bitness(reg_id: u16)
        -> u16
    {
        0
    }
}

