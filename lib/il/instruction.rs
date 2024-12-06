use super::Operation;

#[derive(Debug)] pub struct Instruction
{
    address: u64,
    operation: Operation,
}

impl Instruction
{
    pub fn new(address: u64, operation: Operation)
        -> Self
    {
        Self
        {
            address,
            operation,
        }
    }

    pub fn address(&self)
        -> u64
    {
        self.address
    }

    pub fn operation(&self)
        -> &Operation
    {
        &self.operation
    }
}
