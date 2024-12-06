use super::expression::Expression;

#[derive(Debug)] pub enum Intrinsic
{
    CpuSpecific
    {
        name: String,
        operands: Vec<Expression>,
    },
    MemoryFence,
    Privileged
    {
        name: String,
        operands: Vec<Expression>,
    },
    Simd
    {
        operation: SimdOperation,
        operands: Vec<Expression>,
    },
    Float
    {
        operation: FloatOperation,
        operands: Vec<Expression>,
    },
}

#[derive(Debug)] pub enum SimdOperation
{
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
}

#[derive(Debug)] pub enum FloatOperation
{
    Add,
    Sub,
    Mul,
    Div,
    Sqrt,
    Round,
}
