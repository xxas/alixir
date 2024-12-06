use super::{ Scalar, Expression, Intrinsic };

#[derive(Debug)] pub enum Operation
{   /// Assign the value given in expression to the variable indicated.
    Assign { dst: Scalar, src: Expression },
    /// Store the value in src at the address given in index.
    Store { index: Expression, src: Expression },
    /// Load the value in memory at index and place the result in the variable dst.
    Load { dst: Scalar, index: Expression },
    /// Branch to the value given by target.
    Branch { target: Expression },
    /// Holds an Intrinsic for unmodellable instructions
    Intrinsic { intrinsic: Intrinsic },
    /// An operation that does nothing, and allows for a placeholder `Instruction`
    Nop { placeholder: Option<Box<Operation>> },
}
