pub mod scalar;
pub use scalar::Scalar;

mod expression;
pub use expression::Expression;

mod intrinsic;
pub use intrinsic::Intrinsic;

mod operation;
pub use operation::Operation;

mod instruction;
pub use instruction::Instruction;

mod block;
pub use block::{ BasicBlock, BlockTerminator };

mod function;
pub use function::Function;

mod graph;
pub use graph::{ ProgramGraph, DataFlowAnalysis };
