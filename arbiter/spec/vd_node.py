from typing import Type, Union
from archinfo import ArchAMD64



class VDNode(object):
    def __init__(self, name: Union[str, bytes], is_sink: bool = True) -> None:
        assert len(name) > 0
        self.name = name
        self._is_sink = is_sink
        self._is_source = not is_sink

        arch = ArchAMD64()
        self.register_names = arch.register_names
        self.argument_registers = arch.argument_registers
        self.argument_register_positions = arch.argument_register_positions
        self.ret_offset = arch.ret_offset

        #
        # The following code is to fix a line of code in angr
        # archinfo/arch_amd64.py line 50
        # the argument position of r10 is set to 3
        # This is done for some kernel stuff, but we only use user-space binaries
        # So we delete this key, value pair
        #
        r10 = arch.get_register_offset(name='r10')
        if r10 in self.argument_registers:
            self.argument_registers.remove(r10)

        if r10 in self.argument_register_positions:
            del self.argument_register_positions[r10]

    def __str__(self) -> str:
        return f"VDNode(name={self.name}, is_sink={self.is_sink})"

    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, self.__class__):
            if self.name == __o.name and self.is_sink == __o.is_sink:
                return True
        return False

    def __ne__(self, __o: object) -> bool:
        return not self == __o

    @property
    def is_sink(self) -> bool:
        return self._is_sink

    @is_sink.setter
    def is_sink(self, flag: bool):
        self._is_sink = flag
        self._is_source = not flag

    @property
    def is_source (self) -> bool:
        return self._is_source

    @is_source.setter
    def is_source(self, flag: bool):
        self._is_source = flag
        self._is_sink = not flag


N = Type[VDNode]



class ConstNode(VDNode):
    def __init__(self, value: Union[float, int, bytes]) -> None:
        self.value = value

    def __str__(self) -> str:
        return f"ConstNode(value={self.value})"

    @property
    def register_offset(self) -> int:
        return None

    @property
    def register_name(self) -> str:
        return None



class RetNode(VDNode):
    def __init__(self, name: Union[str,bytes], is_sink: bool = True) -> None:
        super().__init__(name=name, is_sink=is_sink)

    def __str__(self) -> str:
        return f"RetNode(name={self.name}, is_sink={self.is_sink})"

    @property
    def register_offset(self) -> int:
        return self.ret_offset

    @property
    def register_name(self) -> str:
        return self.register_names[self.ret_offset]



class EOFNode(VDNode):
    def __init__(self) -> None:
        # No arguments required for this type of node
        # I cannot imagine a scenario where EOF is used as a source
        # Therefore, set is_sink=True
        super().__init__(name='EOF', is_sink=True)

    def __str__(self) -> str:
        return f"EOFNode(name={self.name}, is_sink={self.is_sink})"

    @property
    def register_offset(self) -> int:
        return self.ret_offset

    @property
    def register_name(self) -> str:
        return self.register_names[self.ret_offset]



class ArgNode(VDNode):
    def __init__(self, name: Union[str,bytes], arg_num: int, is_sink: bool = True) -> None:
        super().__init__(name=name, is_sink=is_sink)

        assert arg_num > 0, "ARG_NUM has to start at index 1"
        self.arg_num = arg_num

    def __str__(self) -> str:
        return f"ArgNode(name={self.name}, arg_num={self.arg_num}, is_sink={self.is_sink})"

    @property
    def register_offset(self) -> int:
        for key in self.argument_registers:
           if self.argument_register_positions[key] == self.arg_num - 1:
               return key

        #
        # If we've reached here, it means that arg_num is greater than 6
        # In AMD64, 7th arg onwards in on the stack
        #
        return None

    @property
    def register_name(self) -> str:
        offset = self.register_offset
        if offset is not None:
            return self.register_names[offset]

        #
        # If we've reached here, it means that arg_num is greater than 6
        # In AMD64, 7th arg onwards in on the stack
        #
        return None



class FirstArg(ArgNode):
    def __init__(self, name: Union[str,bytes], is_sink: bool = True) -> None:
        super().__init__(name, 1, is_sink)

    def __str__(self) -> str:
        return f"FirstArg(name={self.name}, is_sink={self.is_sink})"



class SecondArg(ArgNode):
    def __init__(self, name: Union[str,bytes], is_sink: bool = True) -> None:
        super().__init__(name, 2, is_sink)

    def __str__(self) -> str:
        return f"SecondArg(name={self.name}, is_sink={self.is_sink})"



class ThirdArg(ArgNode):
    def __init__(self, name: Union[str,bytes], is_sink: bool = True) -> None:
        super().__init__(name, 3, is_sink)

    def __str__(self) -> str:
        return f"ThirdArg(name={self.name}, is_sink={self.is_sink})"



class FourthArg(ArgNode):
    def __init__(self, name: Union[str,bytes], is_sink: bool = True) -> None:
        super().__init__(name, 4, is_sink)

    def __str__(self) -> str:
        return f"FourthArg(name={self.name}, is_sink={self.is_sink})"


class FifthArg(ArgNode):
    def __init__(self, name: Union[str,bytes], is_sink: bool = True) -> None:
        super().__init__(name, 5, is_sink)

    def __str__(self) -> str:
        return f"FifthArg(name={self.name}, is_sink={self.is_sink})"



class SixthArg(ArgNode):
    def __init__(self, name: Union[str,bytes], is_sink: bool = True) -> None:
        super().__init__(name, 6, is_sink)

    def __str__(self) -> str:
        return f"SixthArg(name={self.name}, is_sink={self.is_sink})"



def test_vdnode():
    node = VDNode('AA')
    assert node.name == 'AA'
    assert node.is_sink is True
    assert node.is_source is False

    node2 = VDNode(b'AA')
    assert node2.name == b'AA'

    node3 = VDNode('AA', False)
    assert node3.is_sink is False
    assert node3.is_source is True


def test_retnode():
    node = RetNode('Ret')
    assert node.register_name == 'rax'
    assert node.register_offset == 16


def test_argnode():
    try:
        node = ArgNode('AA', 0)
    except AssertionError:
        pass
    node = ArgNode('AA', 7)
    assert node.register_offset == None
    assert node.register_name == None


def test_argnode1():
    node = FirstArg('FA')
    assert node.register_name == 'rdi'
    assert node.register_offset == 72


def test_argnode2():
    node = SecondArg('SA')
    assert node.register_name == 'rsi'
    assert node.register_offset == 64


def test_argnode3():
    node = ThirdArg('TA')
    assert node.register_name == 'rdx'
    assert node.register_offset == 32


def test_argnode4():
    node = FourthArg('FFA')
    assert node.register_name == 'rcx'
    assert node.register_offset == 24


def test_argnode5():
    node = FifthArg('FFFA')
    assert node.register_name == 'r8'
    assert node.register_offset == 80


def test_argnode6():
    node = SixthArg('SSA')
    assert node.register_name == 'r9'
    assert node.register_offset == 88

