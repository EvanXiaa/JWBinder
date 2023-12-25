class WasmInstance:
    def __init__(self, extremity=None, module=None, import_obj=None):
        self.extremity = extremity
        self.module = module
        self.table = None
        self.memory = None
        self.globals = []
        self.import_obj = import_obj
        self.resolve_import(import_obj)

    def resolve_import(self, import_objs):
        for import_obj in import_objs:
            for key, value in import_obj.items():
                if isinstance(value, WasmTable):
                    self.table = value
                elif isinstance(value, WasmMemory):
                    self.memory = value
                elif isinstance(value, WasmGlobal):
                    self.globals.append(value)

    def set_ast(self, ast):
        self.ast = ast

    def set_module(self, module):
        self.module = module


class WasmTable:
    def __init__(self, extremity=None, initial=None):
        self.extremity = extremity
        self.instance = None
        if initial is None:
            self.init = None
            self.element = None
        else:
            self.init = initial[0][1]
            self.element = initial[1][1]

    def set_instance(self, instance):
        self.instance = instance

    def set_init(self, init):
        self.init = init

    def set_element(self, element):
        self.init = element

    def set_extremity(self, extremity):
        self.extremity = extremity


class WasmMemory:
    def __init__(self, extremity=None, initial=None):
        self.extremity = extremity
        self.instance = None
        if initial is None:
            self.init = None
            self.maximum = None
        else:
            self.init = initial[0][1]
            self.maximum = initial[1][1]

    def set_instance(self, instance):
        self.instance = instance

    def set_init(self, init):
        self.init = init

    def set_maximum(self, maximum):
        self.init = maximum

    def set_extremity(self, extremity):
        self.extremity = extremity


class WasmGlobal:
    def __init__(self, extremity=None, initial=None):
        self.extremity = extremity
        self.instance = None
        if initial is None:
            self.value = None
            self.mutable = None
        else:
            self.value = initial[0][1]
            self.mutable = initial[1][1]

    def set_instance(self, instance):
        self.instance = instance

    def set_value(self, value):
        self.value = value

    def set_mutable(self, mutable):
        self.mutable = mutable

    def set_extremity(self, extremity):
        self.extremity = extremity


class WasmModule:
    def __init__(self, extremity=None, initial=None):
        self.extremity = extremity
        self.binary = initial
        self.elements = None

    def set_binary(self, binary):
        self.binary = binary

    def set_extremity(self, extremity):
        self.extremity = extremity

    def set_elements(self,elements):
        self.elements = elements