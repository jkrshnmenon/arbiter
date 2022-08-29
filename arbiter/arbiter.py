import angr
from typing import AnyStr, Optional


from .spec import V
from .analysis import *
from .storage import Storage



class Arbiter():
    def __init__(self, filename: Optional[AnyStr] = None, vd: Optional[V] = None) -> None:
        self.storage = Storage()
        if filename is not None:
            self.add_target(filename)
        if vd is not None:
            self.add_vd(vd)

    def add_target(self, filename: AnyStr):
        self.storage.project = angr.Project(filename, auto_load_libs=False)

    def add_vd(self, vd: V):
        self.storage.vd = vd

    def run_analysis():
        pass


