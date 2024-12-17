use super::{BasicBlock, Expression, Function, Operation};
use petgraph::{
    algo::{dominators, toposort},
    graph::{DiGraph, NodeIndex},
    visit::{Bfs, Dfs, DfsPostOrder},
    Direction,
};
use std::collections::{HashMap, HashSet};

#[derive(Debug)] pub struct ProgramGraph
{   /// The core directed graph structure
    graph: DiGraph<Block, Edge>,

    /// Maps addresses to node indices
    addr_to_node: HashMap<u64, NodeIndex>,

    /// Entry point node
    entry: NodeIndex,
}

#[derive(Debug)] pub struct Block
{   /// The basic block containing instructions
    block: BasicBlock,

    /// Block type for special handling
    kind: BlockKind,
}

#[derive(Debug)] pub enum BlockKind
{
    Entry,
    Exit,
    Normal,
    FunctionEntry(u64), // Function address
    FunctionExit(u64),  // Function address
}

#[derive(Debug)] pub enum Edge
{
    Fallthrough,
    Branch,
    Call,
    Return,
    Exception,
}

impl ProgramGraph
{
    pub fn new() -> Self
    {
        let mut graph = DiGraph::new();
        let entry = graph.add_node(Block {
            block: BasicBlock::new(0),
            kind: BlockKind::Entry,
        });

        Self
        {
            graph,
            addr_to_node: HashMap::from([(0, entry)]),
            entry,
        }
    }

    /// Add a basic block to the graph
    pub fn add_block(&mut self, block: BasicBlock)
        -> NodeIndex
    {
        let addr = block.start_addr();
        let node = self.graph.add_node(Block {
            block,
            kind: BlockKind::Normal,
        });
        self.addr_to_node.insert(addr, node);
        node
    }

    /// Add an edge between blocks
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge_type: Edge)
    {
        self.graph.add_edge(from, to, edge_type);
    }

    /// Get dominators for analysis
    pub fn get_dominators(&self)
        -> dominators::Dominators<NodeIndex>
    {
        dominators::simple_fast(&self.graph, self.entry)
    }

    /// Find loops in the program
    pub fn find_loops(&self)
        -> HashSet<Vec<NodeIndex>>
    {
        let mut loops = HashSet::new();
        let dominators = self.get_dominators();

        // For each edge in the graph
        for edge in self.graph.raw_edges()
        {
            let source = edge.source();
            let target = edge.target();

            // If target dominates source, we found a back edge
            // Check if target is a dominator of source (indicating a back edge)
            if let Some(idom) = dominators.immediate_dominator(source)
            {
                let mut current = idom;
                let mut is_loop = false;

                // Walk up the dominator tree to see if we reach target
                while let Some(next_dom) = dominators.immediate_dominator(current)
                {
                    if next_dom == target
                    {
                        is_loop = true;
                        break;
                    }
                    current = next_dom;
                }

                if is_loop {
                    // Found a loop, collect all nodes in it
                    let mut loop_nodes = vec![source];
                    current = source;

                    while current != target
                    {
                        if let Some(idom) = dominators.immediate_dominator(current)
                        {
                            loop_nodes.push(idom);
                            current = idom;
                        }
                    }
                    loops.insert(loop_nodes);
                }
            }
        }
        loops
    }

    /// Perform dead code elimination
    pub fn eliminate_dead_code(&mut self)
    {
        let mut reachable = HashSet::new();
        let mut dfs = Dfs::new(&self.graph, self.entry);

        // Find all reachable nodes
        while let Some(node) = dfs.next(&self.graph)
        {
            reachable.insert(node);
        }

        // Remove unreachable nodes
        let all_nodes: Vec<_> = self.graph.node_indices().collect();
        for node in all_nodes {
            if !reachable.contains(&node) {
                if let Some(addr) = self
                    .addr_to_node
                    .iter()
                    .find(|(_, &n)| n == node)
                    .map(|(&addr, _)| addr)
                {
                    self.addr_to_node.remove(&addr);
                }
                self.graph.remove_node(node);
            }
        }
    }

    /// Get all paths to a target block
    pub fn paths_to(&self, target: NodeIndex)
        -> Vec<Vec<NodeIndex>>
    {
        let mut paths = Vec::new();
        let mut current_path = vec![self.entry];
        self.find_paths_recursive(self.entry, target, &mut current_path, &mut paths);
        paths
    }

    fn find_paths_recursive(&self, current: NodeIndex, target: NodeIndex, current_path: &mut Vec<NodeIndex>, all_paths: &mut Vec<Vec<NodeIndex>>)
    {
        if current == target
        {
            all_paths.push(current_path.clone());
            return;
        }

        for neighbor in self.graph.neighbors(current)
        {
            if !current_path.contains(&neighbor) {
                current_path.push(neighbor);
                self.find_paths_recursive(neighbor, target, current_path, all_paths);
                current_path.pop();
            }
        }
    }

    /// Check if a path exists between two blocks
    pub fn path_exists(&self, from: NodeIndex, to: NodeIndex)
        -> bool
    {
        let mut dfs = Dfs::new(&self.graph, from);
        while let Some(node) = dfs.next(&self.graph) {
            if node == to {
                return true;
            }
        }
        false
    }

    /// Get all function entry points
    pub fn get_function_entries(&self)
        -> Vec<NodeIndex>
    {
        self.graph
            .node_indices()
            .filter(|&n| matches!(self.graph[n].kind, BlockKind::FunctionEntry(_)))
            .collect()
    }

    /// Analyze data flow between blocks
    pub fn analyze_data_flow(&self) -> DataFlowAnalysis
    {
        DataFlowAnalysis::new(self)
    }
}

pub struct DataFlowAnalysis
{
    def_use: HashMap<NodeIndex, (HashSet<String>, HashSet<String>)>,
}

impl DataFlowAnalysis
{
    pub fn new(graph: &ProgramGraph)
        -> Self
    {
        let mut def_use = HashMap::new();

        // For each block in the graph
        for node in graph.graph.node_indices()
        {
            let block = &graph.graph[node].block;
            let mut definitions = HashSet::new();
            let mut uses = HashSet::new();

            // Analyze each instruction in the block
            for inst in block.instructions()
            {
                match inst.operation()
                {
                    Operation::Assign { dst, src } =>
                    {
                        definitions.insert(dst.get_str().to_string());
                        Self::collect_uses_from_expr(src, &mut uses);
                    }
                    Operation::Load { dst, index, .. } =>
                    {
                        definitions.insert(dst.get_str().to_string());
                        Self::collect_uses_from_expr(index, &mut uses);
                    }
                    Operation::Store { index, src, .. } =>
                    {
                        Self::collect_uses_from_expr(index, &mut uses);
                        Self::collect_uses_from_expr(src, &mut uses);
                    }
                    // Add other cases as needed
                    _ => {}
                }
            }

            def_use.insert(node, (definitions, uses));
        }

        Self { def_use }
    }

    fn collect_uses_from_expr(expr: &Expression, uses: &mut HashSet<String>)
    {
        match expr
        {
            Expression::Scalar(scalar) =>
            {
                uses.insert(scalar.get_str().to_string());
            }
            Expression::Add(left, right)
            | Expression::Sub(left, right)
            | Expression::Mul(left, right) =>
            {
                Self::collect_uses_from_expr(left, uses);
                Self::collect_uses_from_expr(right, uses);
            }
            // TODO: Expand expressions.
            _ => {}
        }
    }

    pub fn get_definitions(&self, node: NodeIndex) -> Option<&HashSet<String>>
    {
        self.def_use.get(&node).map(|(defs, _)| defs)
    }

    pub fn get_uses(&self, node: NodeIndex) -> Option<&HashSet<String>>
    {
        self.def_use.get(&node).map(|(_, uses)| uses)
    }
}
