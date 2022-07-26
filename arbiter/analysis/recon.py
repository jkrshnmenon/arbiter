import angr
from tqdm import tqdm
from typing import Type


from ..storage import S


class Recon():
    """
    A class to perform the first step of Arbiter analysis
    Static sink identification
    """
    def __init__(self, storage: S) -> None:
        self.storage = storage

