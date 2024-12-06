use std::collections::HashSet;
use super::{ Instruction, Operation, Expression };

#[derive(Debug)] pub struct BasicBlock
{
    /// Starting address of the block
    start_addr: u64,

    /// Ending address of the block
    end_addr: u64,

    /// List of instructions in the block
    instructions: Vec<Instruction>,

    /// Block terminator
    terminator: BlockTerminator,

    /// Block metadata for analysis
    metadata: BlockMetadata,
}

#[derive(Debug, Clone, Default)] pub struct BlockMetadata
{
    /// Variables defined in this block
    definitions: HashSet<String>,

    /// Variables used in this block
    uses: HashSet<String>,

    /// Memory addresses read
    memory_reads: HashSet<u64>,

    /// Memory addresses written
    memory_writes: HashSet<u64>,

    /// Whether this block can throw an exception
    can_throw: bool,

    /// Block execution frequency (if profiling data available)
    execution_count: Option<u64>,
}

#[derive(Debug, Clone)] pub enum BlockTerminator
{
    /// Return from function
    Return,

    /// Unconditional jump to address
    UnconditionalBranch(u64),

    /// Conditional branch with true/false targets
    ConditionalBranch
    {
        condition: Expression,
        target_true: u64,
        target_false: u64,
    },

    /// Function call with return address
    Call
    {
        target: u64,
        return_addr: u64,
    },

    /// Indirect jump through register/memory
    IndirectBranch
    {
        target: Expression,
    },
    /// Fall through to next block
    Fall,

    /// System call
    Syscall
    {
        number: u64,
    },

    /// Exception/interrupt
    Exception
    {
        vector: u64,
    },
}

impl BasicBlock
{
    pub fn new(start_addr: u64)
        -> Self
    {
        Self
        {
            start_addr,
            end_addr: start_addr,
            instructions: Vec::new(),
            terminator: BlockTerminator::Fall,
            metadata: BlockMetadata::default(),
        }
    }

    /// Add an instruction to the block
    pub fn add_instruction(&mut self, instruction: Instruction)
    {
        self.update_metadata(&instruction);
        self.end_addr = instruction.address();
        self.instructions.push(instruction);
    }

    /// Set the block terminator
    pub fn set_terminator(&mut self, terminator: BlockTerminator)
    {
        self.terminator = terminator;
    }

    /// Get block start address
    pub fn start_addr(&self)
        -> u64
    {
        self.start_addr
    }

    /// Get block end address
    pub fn end_addr(&self)
        -> u64
    {
        self.end_addr
    }

    /// Get block size
    pub fn size(&self)
        -> u64
    {
        self.end_addr - self.start_addr
    }

    /// Get instruction slice
    pub fn instructions(&self)
        -> &[Instruction]
    {
        &self.instructions
    }

    /// Get mutable instruction slice
    pub fn instructions_mut(&mut self)
        -> &mut Vec<Instruction>
    {
        &mut self.instructions
    }

    /// Get block terminator
    pub fn terminator(&self)
        -> &BlockTerminator
    {
        &self.terminator
    }

    /// Get block metadata
    pub fn metadata(&self)
        -> &BlockMetadata
    {
        &self.metadata
    }

    /// Check if address is within block range
    pub fn contains_address(&self, addr: u64)
        -> bool
    {
        addr >= self.start_addr && addr <= self.end_addr
    }

    /// Get instruction at specific address
    pub fn get_instruction_at(&self, addr: u64)
        -> Option<&Instruction>
    {
        self.instructions.iter().find(|inst| inst.address() == addr)
    }

    /// Update block metadata based on instruction
    fn update_metadata(&mut self, instruction: &Instruction)
    {
        match instruction.operation()
        {
            Operation::Assign { dst, src } =>
            {
                self.metadata.definitions.insert(dst.get_str().to_string());
                self.collect_uses_from_expr(src);
            },
            Operation::Load { dst, index, .. } =>
            {
                self.metadata.definitions.insert(dst.get_str().to_string());
                self.collect_uses_from_expr(index);
                // Could add memory_reads here if index is constant
            },
            Operation::Store { index, src, .. } =>
            {
                self.collect_uses_from_expr(index);
                self.collect_uses_from_expr(src);
                // Could add memory_writes here if index is constant
            },
            Operation::Intrinsic { .. } =>
            {
                self.metadata.can_throw = true;
            },
            _ => {}
        }
    }

    /// Collect variable uses from expression
    fn collect_uses_from_expr(&mut self, expr: &Expression)
    {
        match expr
        {
            Expression::Scalar(scalar) =>
            {
                self.metadata.uses.insert(scalar.get_str().to_string());
            },
            Expression::Add(left, right) |
            Expression::Sub(left, right) |
            Expression::Mul(left, right) =>
            {
                self.collect_uses_from_expr(left);
                self.collect_uses_from_expr(right);
            },
            // Add other cases as needed
            _ => {}
        }
    }

    /// Check if block modifies a variable
    pub fn modifies_variable(&self, var: &str)
        -> bool
    {
        self.metadata.definitions.contains(var)
    }

    /// Check if block uses a variable
    pub fn uses_variable(&self, var: &str)
        -> bool
    {
        self.metadata.uses.contains(var)
    }

    /// Get successor addresses
    pub fn successor_addresses(&self)
        -> Vec<u64>
    {
        match &self.terminator
        {
            BlockTerminator::UnconditionalBranch(addr) => vec![*addr],
            BlockTerminator::ConditionalBranch { target_true, target_false, .. } =>
            {
                vec![*target_true, *target_false]
            },
            BlockTerminator::Call { target, return_addr } =>
            {
                vec![*target, *return_addr]
            },
            BlockTerminator::Fall =>
            {
                vec![self.end_addr + 1]
            },
            _ => Vec::new()
        }
    }
}

// Additional helper implementations
impl BlockTerminator
{   /// Check if terminator is conditional
    pub fn is_conditional(&self)
        -> bool
    {
        matches!(self, BlockTerminator::ConditionalBranch { .. })
    }

    /// Check if terminator is a call
    pub fn is_call(&self)
        -> bool
    {
        matches!(self, BlockTerminator::Call { .. })
    }

    /// Get target addresses
    pub fn target_addresses(&self)
        -> Vec<u64>
    {
        match self
        {
            BlockTerminator::UnconditionalBranch(addr) => vec![*addr],
            BlockTerminator::ConditionalBranch { target_true, target_false, .. } =>
            {
                vec![*target_true, *target_false]
            },
            BlockTerminator::Call { target, .. } => vec![*target],
            _ => Vec::new()
        }
    }
}
