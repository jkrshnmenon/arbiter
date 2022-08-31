import angr
import networkx as nx
from tqdm import tqdm
from typing import Type, List, Dict


from ..storage import *
from ..spec import *

F = Type[angr.knowledge_plugins.functions.function.Function]

class ControlFlow():
    """
    A class to perform the first step of Arbiter analysis
    Static sink identification
    """
    def __init__(self, storage: S) -> None:
        self.storage = storage
        self.storage.cfg = self.storage.project.analyses.CFG()
    
    @property
    def cfg(self):
        return self.storage.cfg
    
    @property
    def vd(self):
        return self.storage.vd
    
    def find_marker_nodes(self, marker_map: Dict[int, List[M]], vd_node: N) -> List[M]:
        """Find a marker node corresponding to the VDNode

        Args:
            marker_map (Dict[int, List[M]]): The dictionary of function addresses and their markers
            vd_node (N): The VDNode object
        """
        marker_nodes = []
        for addr in marker_map:
            for sinkmarker in marker_map[addr]:
                if sinkmarker.marker == vd_node:
                    marker_nodes.append(sinkmarker)
        
        return marker_nodes
    
    def has_control_flow(self, root_node: M, child_node: M) -> bool:
        """Check if a control flow path exists between a root and child nodes

        Args:
            root_node (M): The root node to start from
            child_node (M): The child node to search for a path to

        Returns:
            bool: True if a path exists from root node to child node. False otherwise
        """
        root_func, child_func = root_node.function, child_node.function
        
        # First check if both nodes are in the same function
        if root_func == child_func:
            # Check the function graph for a path
            graph = root_func.graph
            src = root_func.get_node(root_node.block.addr)
            dst = child_func.get_node(child_node.block.addr)
        else:
            # Check the callgraph for a path from source function to destination function
            graph = self.cfg.kb.callgraph
            src = root_func.addr
            dst = child_func.addr
        
        return nx.has_path(graph, src, dst)
    
    def control_flow_filter(self, root_node: M, candidate_nodes: List[M]) -> List[M]:
        """Filter out nodes that have a control flow path from root node

        Args:
            root_node (M): The root node to start from
            candidate_nodes (List[M]): The candidate nodes to search control flow paths to

        Returns:
            List[M]: A list of marker nodes that have a path from the root node
        """
        child_nodes = []
        for node in candidate_nodes:
            if self.has_control_flow(root_node=root_node, child_node=node):
                child_nodes.append(node)
        
        return child_nodes
    
    def recursively_find_flow(self, marker_map: Dict[int, List[M]], vd_path: List[N], root_node: M) -> List[M]:
        """Recursively find possible flows that match VD

        Args:
            marker_map (Dict[int, List[M]]): The dictionary of function addresses and their markers
            vd_path (List[N]): The VD marker path
            root_node (M): The marker node to start with

        Returns:
            List[M]: A list of marker nodes that correspond to VD node path
        """
        if len(vd_path) == 0:
            return []

        marker_nodes = self.find_marker_nodes(marker_map=marker_map, vd_node=vd_path[0])
        candidate_nodes = self.control_flow_filter(root_node=root_node, candidate_nodes=marker_nodes)

        if len(vd_path) == 1:
            if len(candidate_nodes) == 0:
                return []
            else:
                return [[x] for x in candidate_nodes]
        else:
            total_flows = []
            for node in candidate_nodes:
                flows = self.recursively_find_flow(marker_map=marker_map, vd_path=vd_path[1:], root_node=node)
                for tmp in flows:
                    total_flows.append([root_node].extend(tmp))
        
        return total_flows

    
    def find_marker_flow(self, marker_map: Dict[int, List[M]], vd_path: List[N]) -> List[List[M]]:
        """Find a sequence of markers specified in path in the binary

        Args:
            marker_map (Dict[int, List[M]]): The dictionary of function addresses and their markers
            vd_path (List[N]): The path of VDNodes
        """
        assert len(vd_path) > 0, f"VD Path is empty"
        root_nodes = self.find_marker_nodes(marker_map=marker_map, vd_node=vd_path[0])
        if len(vd_path) == 1:
            return [list(x) for x in root_nodes]
        
        flows = []
        for root in root_nodes:
            marker_flow = self.recursively_find_flow(marker_map=marker_map, vd_path=vd_path[1:], root_node=root)
            for tmp in marker_flow:
                if len(vd_path) == 2:
                    tmp = [root] + tmp
                flows.append(tmp)
        
        return flows
    
    def identify_flows(self, marker_map: Dict[int, List[M]]) -> None:
        """Identify flows between sources and sinks and verify control-depedencies

        Args:
            marker_map (Dict[int, List[M]]): The dictionary of function addresses and their markers
        """
        flows = []
        for path in self.vd.iterate_paths():
            marker_flow = self.find_marker_flow(marker_map=marker_map, vd_path=path)
            flows.extend(marker_flow)
        
        for path in flows:
            sf = SinkFlow(path=path)
            self.storage.add_result(thing=sf)

    def get_markers(self, callees: List[str], nodes: List[N], func: F) -> List[M]:
        markers = []
        # Iterate over sinks first
        for tmp in nodes:
            assert isinstance(tmp, VDNode), f"Invalid object {tmp}"
            if isinstance(tmp, EOFNode):
                # TODO: Find block with "ret" instruction
                raise NotImplemented
                # ret_block = None
                # markers.append(SinkMarker(tmp, ret_block, func))
                # continue
            for callee_name, call_block in callees:
                if tmp.name in callee_name:
                    markers.append(SinkMarker(tmp, call_block, func))
        
        return markers

    def check_one_func(self, func: F) -> List[M]:
        """Identify source and sink nodes in one function

        Args:
            func (F): The angr function object

        Returns:
            List[M]: A list of SinkMarkers for this function
        """

        # Get list of callee's
        callees = []
        for call_site in func.get_call_sites():
            try:
                call_target = func.get_call_target(call_site)
                call_target_name = self.cfg.functions.function(call_target).name
                callees.append((call_target_name, self.cfg.get_any_node(call_site).block))
            except:
                continue

        sinks = self.get_markers(callees=callees, nodes=self.vd.sinks, func=func)
        sources = self.get_markers(callees=callees, nodes=self.vd.sources, func=func)
        return sinks + sources

    def analyze_all(self):
        marker_map = {}
        for addr, func in tqdm(self.cfg.functions.items(), desc='Identifying functions'):
            tmp = self.check_one_func(func=func)
            if len(tmp) > 0:
                marker_map[addr] = tmp
        
        self.identify_flows(marker_map)


