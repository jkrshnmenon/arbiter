import angr
import networkx as nx
from tqdm import tqdm
from typing import Type, List, Dict

from ..storage import *
from ..spec import *



class DataFlow(object):
    """A class to perform the DataFlow analysis across SinkFlows
    """
    def __init__(self, storage: S) -> None:
        """

        Args:
            storage (S): The Arbiter Storage object
        """
        self.storage = storage
    
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
        # Verify data flow using backends
    
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