use std::sync::Arc;
use super::Scalar;
use derive_more::Display;

#[derive(Debug, Display, Clone)] pub enum Expression
{
    // Basic types
    #[display(  r#"var<"{}", {}>"#, _0.get_str(), _0.bitness())]Scalar(Scalar),
    #[display(r#"const<"{}", {}>"#, _0.get_str(), _0.bitness())]Constant(Scalar),

    // Arithmetic operations
    #[display("({_0} + {_1})")] Add(Arc<Expression>, Arc<Expression>),
    #[display("({_0} - {_1})")] Sub(Arc<Expression>, Arc<Expression>),
    #[display("({_0} * {_1})")] Mul(Arc<Expression>, Arc<Expression>),

    // Division operations
    #[display("({_0} /u {_1})")] DivUnsigned(Arc<Expression>, Arc<Expression>),
    #[display("({_0} %u {_1})")] ModUnsigned(Arc<Expression>, Arc<Expression>),
    #[display("({_0} /s {_1})")] DivSigned(Arc<Expression>, Arc<Expression>),
    #[display("({_0} %s {_1})")] ModSigned(Arc<Expression>, Arc<Expression>),

    // Bitwise operations
    #[display("({_0} & {_1})")]  BitwiseAnd(Arc<Expression>, Arc<Expression>),
    #[display("({_0} | {_1})")]  BitwiseOr(Arc<Expression>, Arc<Expression>),
    #[display("({_0} ^ {_1})")]  BitwiseXor(Arc<Expression>, Arc<Expression>),
    #[display("({_0} << {_1})")] ShiftLeft(Arc<Expression>, Arc<Expression>),
    #[display("({_0} >> {_1})")] ShiftRight(Arc<Expression>, Arc<Expression>),

    // Comparison operations
    #[display("({_0} == {_1})")] Equal(Arc<Expression>, Arc<Expression>),
    #[display("({_0} != {_1})")] NotEqual(Arc<Expression>, Arc<Expression>),
    #[display("({_0} <s {_1})")] LessThanSigned(Arc<Expression>, Arc<Expression>),
    #[display("({_0} <u {_1})")] LessThanUnsigned(Arc<Expression>, Arc<Expression>),

    // Type conversion operations
    #[display("zext({bits}, {expr})")] ZeroExtend
    {
        bits: usize,
        expr: Arc<Expression>,
    },

    #[display("sext({bits}, {expr})")] SignExtend
    {
        bits: usize,
        expr: Arc<Expression>,
    },
    #[display("trunc({bits}, {expr})")] Truncate
    {
        bits: usize,
        expr: Arc<Expression>,
    },

    // Control flow
    #[display(r"if ({_0}) {_1} else {_2}")] IfThenElse(Arc<Expression>, Arc<Expression>, Arc<Expression>),
}
