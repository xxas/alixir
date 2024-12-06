use std::collections::HashMap;
use super::BasicBlock;

#[derive(Debug)] pub struct Function
{
    name:           Option<String>,
    blocks:         HashMap<u64, BasicBlock>,
    entry_block:    u64,
}

impl Function
{
    pub fn new<T: Into<String>>(name: Option<T>, entry_block: u64)
        -> Self
    {
        Self
        {
            name: name.map(T::into),
            blocks: HashMap::new(),
            entry_block,
        }
    }

    pub fn add_block(&mut self, address: u64, block: BasicBlock)
    {
        self.blocks.insert(address, block);
    }

    pub fn get_block(&self, address: u64)
        -> Option<&BasicBlock>
    {
        self.blocks.get(&address)
    }

    pub fn entry_block(&self)
        -> u64
    {
        self.entry_block
    }
}
