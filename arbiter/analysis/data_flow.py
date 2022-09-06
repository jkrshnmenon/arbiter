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
    
    def prep_data_flow(self, flow: S) -> None:
        """Prepare all nodes in the data flow by creating DataMarkers

        Args:
            flow (S): A SinkFlow object
        """
        for sinkmarker in flow.nodes:
            assert isinstance(sinkmarker, VDNode)
            datamarker = DataMarker(sinkmarker)
    
    def resolve_data_flow(self, flow: S):
        """Resolve a data flow backwards from sink to source

        Args:
            flow (S): A SinkFlow object
        """
        sources, sinks = flow.sources, flow.sinks

    
    def analyze_all(self):
        """Analyze all of the SinkFlows
        """
        for flow in self.storage.iter_sinks():
            self.resolve_data_flow(flow)