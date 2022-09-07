import angr
import networkx as nx
from tqdm import tqdm
from typing import Type, List, Dict

from ..storage import *
from ..spec import *
from backends import ArbiterBackend



class DataFlow(object):
    """A class to perform the DataFlow analysis across SinkFlows
    """
    def __init__(self, storage: S) -> None:
        """

        Args:
            storage (S): The Arbiter Storage object
        """
        self.storage = storage
        if self.storage.backend_name == 'Arbiter':
            self.backend = ArbiterBackend(self.storage)
        else:
            raise NotImplementedError
    
    @property
    def cfg(self):
        return self.storage.cfg
    
    @property
    def vd(self):
        return self.storage.vd

    def prep_data_flow(self, flow: S) -> Dict[M, DM]:
        """Prepare all nodes in the data flow by creating DataMarkers

        Args:
            flow (S): A SinkFlow object
        """
        dataflow = {}
        for sinkmarker in flow.nodes:
            assert isinstance(sinkmarker, VDNode)
            datamarker = DataMarker(sinkmarker)
            dataflow[sinkmarker] = datamarker
        
        return dataflow
    
    def verify_data_flow(self, flow: S, marker_map: Dict[M, DM]) -> bool:
        """Verify whether a data flow exists from the start to the end of the flow

        Args:
            flow (S): A SinkFlow object containing SinkMarkers
            marker_map (Dict[M, DM]): A dictionary that maps SinkMarker objects to DataMarker objects

        Returns:
            bool: True if the data flow could be verified, False otherwise
        """

        # Iterate over each tuple of nodes in flow (backwards or forwards)
        window = 2
        for i in range(len(flow)-window+1):

            src, dst = flow[i:i+window]

            if isinstance(src, MetaNode):
                edges = []
                for child_node in src.nodes:
                    for target_node in src.edge_targets(node=child_node, incoming=False):
                        if isinstance(dst, MetaNode) and target_node in dst.nodes:
                            edges.append([child_node, target_node])
                        elif target_node == dst:
                            edges.append([child_node, target_node])
                assert len(edges) > 0
                for edge in edges:
                    if self.verify_data_flow(flow=edge, marker_map=marker_map) is False:
                        return False
                continue

            elif isinstance(dst, MetaNode):
                # We know that src is not a MetaNode
                edges = []
                for child_node in dst.nodes:
                    for target_node in dst.edge_targets(node=child_node, incoming=True):
                        assert not isinstance(src, MetaNode)
                        if target_node == src:
                            edges.append([target_node, child_node])
                assert len(edges) > 0
                for edge in edges:
                    if self.verify_data_flow(flow=edge, marker_map=marker_map) is False:
                        return False
                continue

            # No MetaNodes here
            if self.backend.verify_edge_flow(src_node=marker_map[src], dst_node=marker_map[dst]) is False:
                return False
        
        return True
    
    def resolve_data_flow(self, flow: S):
        """Resolve a data flow backwards from sink to source

        Args:
            flow (S): A SinkFlow object
        """
        dataflow_map = {}
        dataflow_map.update(self.prep_data_flow(flow=flow))

        if self.verify_data_flow(flow=flow, marker_map=dataflow_map):
            df = DataFlow(flow)
            self.storage.add_result(thing=df)

    
    def analyze_all(self):
        """Analyze all of the SinkFlows
        """
        for flow in self.storage.iter_sinks():
            self.resolve_data_flow(flow)