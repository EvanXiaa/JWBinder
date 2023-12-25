import base64
import copy
import datetime
import json
import os
import subprocess
import escodegen
import hooker.wasmObject
import node as _node
import scope
from build_ast import ast_to_ast_nodes, save_json, build_json
from build_pdg import get_data_flow, find_nearest_parent, simple_taint_analysis_instance
from control_flow import control_flow_update
from data_flow import get_nearest_statement_son, df_scoping, get_nearest_statement

rootdir = "/Users/xiayifan/Programs/js_static-main/demo/test"
temp_wasm = "/Users/xiayifan/Programs/js_static-main/demo/temp.wasm"
module_json = "/Users/xiayifan/Programs/js_static-main/demo/module.json"
wasm2wat = "/opt/homebrew/bin/wasm2wat"
node_path = "/opt/homebrew/bin/node"
parser_path = "/Users/xiayifan/WebstormProjects/Parser/parser_new.js"


wasmInstances = []
wasm_inits = []
wasm_tables = []
wasm_memories = []
wasm_globals = []
wasm_modules = []
wasm_instances = []
orphan_modules = []
is_unwrapped = True


def simple_taint_analysis(node):
    children = node.children
    if len(children) > 0:
        for child in children:
            simple_taint_analysis(child)
    if node.name == 'Literal' and ((isinstance(node.value, str) and node.value.startswith(magic_num_base64)) or (
            isinstance(node.attributes['value'], str) and node.attributes["value"].startswith(magic_num_base64))):
        # it seems we find a wasm binary
        parent = node.parent
        if parent.name == 'VariableDeclarator' or parent.name == 'AssignmentExpression':
            left_value = parent.children[0]
            if left_value.name == "Identifier":
                left_value.WASMSource = node
                for ddc in left_value.data_dep_children:
                    ddc.extremity.WASMSource = node
            else:
                assert 1, "what's wrong here"
        else:
            wasmBytes = node.value if node.value is not None else node.attributes["value"]
            WASMSource = hooker.wasmObject.WasmModule(node, wasmBytes)
            orphan_modules.append(WASMSource)
    elif node.name == 'Identifier' and node.WASMSource is not None:
        parent = node.parent
        # the simplest assignment
        if parent.name == 'VariableDeclarator' or parent.name == 'AssignmentExpression':
            left_value = parent.children[0]
            if left_value.name == "Identifier":
                left_value.WASMSource = node.WASMSource
                for ddc in left_value.data_dep_children:
                    ddc.extremity.WASMSource = node.WASMSource
            else:
                assert 1, "what's wrong here"
        else:
            # print(parent.name) corner case?
            nearest_parent = find_nearest_parent(parent)
            if nearest_parent is not None:
                left_value = nearest_parent.children[0]
                if left_value.name == "Identifier":
                    left_value.WASMSource = node.WASMSource
                    for ddc in left_value.data_dep_children:
                        ddc.extremity.WASMSource = node.WASMSource
                else:
                    assert 1, "what's wrong here"
    elif node.WASMSource is not None:
        for ddc in node.data_dep_children:
            ddc.extremity.WASMSource = node.WASMSource


def copy_subtree(origin, parent, id_list):
    id_list.append(origin.id)
    node_type = type(origin)
    new = node_type(origin.name, parent)
    new.id = _node.Node.id
    _node.Node.id += 1
    for child in origin.children:
        new.children.append(copy_subtree(child, new, id_list))
    for k, v in origin.__dict__.items():
        if k in ['name', 'filename', 'attributes', 'body', 'body_list', 'value', 'update_value', 'code', 'fun',
                 'fun_name', 'fun_params', 'fun_return', 'retraverse', 'called', 'fun_intern_name']:
            setattr(new, k, v)
        elif k == "data_dep_parents":
            temp = []
            for d_dep in v:
                if d_dep.extremity.id not in id_list and d_dep.extremity.id < id_list[0]:
                    temp.append(_node.Dependence("data dependency", d_dep.extremity, d_dep.label))
                    d_dep.extremity.data_dep_children.append(_node.Dependence("data dependency", new, d_dep.label))
            setattr(new, k, temp)
        elif k in ['statement_dep_parents', 'statement_dep_children', 'provenance_children', 'provenance_parents',
                   'data_dep_children', 'control_dep_parents', 'control_dep_children']:
            setattr(new, k, [])
        elif k in ['seen_provenance', 'provenance_parents_set', 'provenance_children_set']:
            setattr(new, k, ())
        elif k not in ['parent', 'children', 'WASMSource', "id", "fun_param_parents", '"fun_param_children', 'last_return', "id_order"]:
            print("what is this???????")
    return new


def search_property(node):
    # todo: Are there nest property deeper than 3? It seems NO.
    # the  first child should be an identifier, normally the a of a.b
    import_obj = {}
    external_name = node.children[0].attributes['name']
    if len(node.children) > 1:
        internal_object = node.children[1]
        for internal_property in internal_object.children:
            internal_name = internal_property.children[0].attributes['name']
            if len(internal_property.children) > 1:
                internal_object = internal_property.children[1]
                import_obj[external_name + "." + internal_name] = internal_object
            else:
                import_obj[external_name.concat('.').concat(internal_name)] = ''
    else:
        import_obj[external_name] = ''
    return import_obj


def searchImportObjects(node, imports):
    if node.name == "ObjectExpression":
        for property in node.children:
            if property.name == "Property":
                imports.append(search_property(property))
    return imports


def update_dataChild_WSource(node):
    for i, ddc in enumerate(node.data_dep_children):
        ddc.extremity.WASMSource = node.WASMSource
        update_dataChild_WSource(ddc.extremity)


def searchWasmBytes(node, wasmBytes):
    if node.WASMSource is not None:
        if node.WASMSource not in wasmBytes:
            wasmBytes.append(node.WASMSource)
    for child in node.children:
        if child.WASMSource is not None:
            if child.WASMSource not in wasmBytes:
                wasmBytes.append(child.WASMSource)
        searchWasmBytes(child, wasmBytes)


def searchWasmModules(node, wasmModules):
    if node.WASMSource is not None:
        if node.WASMSource not in wasmModules:
            wasmModules.append(node.WASMSource)
    for child in node.children:
        if child.WASMSource is not None and isinstance(child.WASMSource, hooker.wasmObject.WasmModule):
            if child.WASMSource not in wasmModules:
                wasmModules.append(child.WASMSource)
        searchWasmBytes(child, wasmModules)


def collect_WASM_init(pdg):
    for child in pdg.children:
        if child.name == "Identifier" and child.attributes["name"] == "WebAssembly":
            wasm_inits.append(child)
        collect_WASM_init(child)


def getProperty(node):
    for child in node.children:
        if child.body == "value":
            value = child.attributes["value"]
        elif child.body == "key":
            key = child.attributes["value"]
        else:
            print("???getProperty")
    return [key, value]


def extractTable(pdg):
    tableArgs = []
    parent = pdg.parent
    if parent.name == "NewExpression":
        init = parent.children[1]
        if init.name == "ObjectExpression" and init.body == "arguments":
            for child in init.children:
                tableArgs.append(getProperty(child))
        else:
            assert 0, "other table"
    else:
        assert 0, "other table"
    if parent.body == "init":
        wasm_tables.append(hooker.wasmObject.WasmTable(parent.parent.children[0], tableArgs))


def extractGlobal(pdg):
    GlobalArgs = []
    parent = pdg.parent
    if parent.name == "NewExpression":
        init = parent.children[1]
        if init.name == "ObjectExpression" and init.body == "arguments":
            for child in init.children:
                GlobalArgs.append(getProperty(child))
        else:
            assert 0, "other global"
    else:
        assert 0, "other global"
    if parent.body == "init":
        wasm_memories.append(hooker.wasmObject.WasmGlobal(parent.parent.children[0], GlobalArgs))


def extractMemory(pdg):
    memoryArgs = []
    parent = pdg.parent
    if parent.name == "NewExpression":
        init = parent.children[1]
        if init.name == "ObjectExpression" and init.body == "arguments":
            for child in init.children:
                memoryArgs.append(getProperty(child))
        else:
            assert 0, "other memory"
    else:
        assert 0, "other memory"
    if parent.body == "init":
        wasm_memories.append(hooker.wasmObject.WasmMemory(parent.parent.children[0], memoryArgs))


def extractModule(node):
    ModuleArgs = []
    parent = node.parent
    # simplest situation
    if parent.name == "NewExpression":
        init = parent.children[1]
        wasm_bytes = []
        searchWasmBytes(init, wasm_bytes)
        if len(wasm_bytes) == 0:
            return
        elif len(wasm_bytes) > 1:
            print("multiple wasm bytes")
    else:
        print("other module")
    if parent.body == "init":
        grandParent = parent.parent
        wasmModule = grandParent.children[0]
        if wasmModule.name == "Identifier":
            wasmModule.WASMSource = hooker.wasmObject.WasmModule(wasmModule, wasm_bytes[0])
            wasm_modules.append(wasmModule.WASMSource)
            update_dataChild_WSource(wasmModule)
        else:
            assert 0, "what' wrong here"
    else:
        wasmModule = node
        wasmModule.WASMSource = hooker.wasmObject.WasmModule(wasmModule, wasm_bytes[0])
        wasm_modules.append(wasmModule.WASMSource)

def extractInstance(node):
    parent = node.parent
    import_object = []
    # simplest situation
    if parent.name == "NewExpression":
        is_pure_instance = True if len(parent.children) == 2 else False
        if is_pure_instance:
            init = parent.children[1]
            wasmModules = []
            searchWasmModules(init, wasmModules)
            if len(wasmModules) == 0:
                return
        else:
            init = parent.children[1]
            imports = parent.children[2]
            wasmModules = []
            searchWasmModules(init, wasmModules)
            if len(wasmModules) == 0:
                return
            searchImportObjects(imports, import_object)
    else:
        print("???other instance？")
    if parent.body == "init":
        grandParent = parent.parent
        wasmInstance = grandParent.children[0]
        if wasmInstance.name == "Identifier":
            wasmInstance.WASMSource = hooker.wasmObject.WasmInstance(wasmInstance, wasmModules[0], import_object)
            wasm_instances.append(wasmInstance.WASMSource)
            update_dataChild_WSource(wasmInstance)
    else:
        assert 0, "what's wrong here"


def collect_WASM_object(inits):
    for init in inits:
        parent = init.parent
        callee = parent.children[1]
        if callee.name == "Literal":
            method = callee.attributes["value"]
        elif callee.name == "Identifier":
            method = callee.attributes["name"]

        if method == "Table":
            extractTable(parent)
        elif method == "Global":
            extractGlobal(parent)
        elif method == "Memory":
            extractMemory(parent)
        elif method == "Module":
            extractModule(parent)


def initial_WASM_instance(inits):
    for init in inits:
        parent = init.parent
        callee = parent.children[1]
        if callee.name == "Literal":
            method = callee.attributes["value"]
        elif callee.name == "Identifier":
            method = callee.attributes["name"]
        elif method == "Instance":
            extractInstance(parent)


def clear_subtree(root):
    """
    this function will iteratively clear ht data dependency of handled subtree
    :param root:
    :return:
    """
    for child in root.children:
        clear_subtree(child)
    if isinstance(root, _node.Value):
        root.provenance_parents_set.clear()
        root.provenance_children_set.clear()
        root.seen_provenance.clear()
    if isinstance(root, _node.Identifier):
        for parent in root.data_dep_parents:
            p_ex = parent.extremity
            for d_dep in p_ex.data_dep_children:
                if d_dep.extremity == p_ex:
                    p_ex.data_dep_children.remove(d_dep)
                    break
        for child in root.data_dep_children:
            c_ex = child.extremity
            for d_dep in c_ex.data_dep_parents:
                if d_dep.extremity == c_ex:
                    c_ex.data_dep_parents.remove(d_dep)
                    break


# It seems now we don't need this
# def chaos_update_subtree(root, id_list=[]):
#     """
#     chaos_update will preserve the data dep parents originating from outer scope
#     :param root:
#     :param id_list:
#     :return:
#     """
#     root.id = _node.Node.id
#     _node.Node.id += 1
#     id_list.append(root.id)
#     for child in root.children:
#         chaos_update_subtree(child)
#     # it is empty
#     # if isinstance(root, _node.Value):
#     #     root.provenance_parents_set.clear()
#     #     root.provenance_children_set.clear()
#     #     root.seen_provenance.clear()
#     if isinstance(root, _node.Identifier):
#         for parent in root.data_dep_parents:
#             p_ex = parent.extremity
#             if p_ex not in id_list:
#                 p_ex.data_dep_children.append(_node.Dependence('data dependency', root, 'data'))
#             else:
#                 for d_dep in p_ex.data_dep_children:
#                     if d_dep.extremity == p_ex:
#                         p_ex.data_dep_children.remove(d_dep)
#                         break


def pure_replace_statement(origin, new):
    """
    when we want to replace a handled subtree with artifact subtree
    :param origin:
    :param new:
    :return:
    """
    clear_subtree(origin)
    new.parent = origin.parent

    # adjust new's body according to origin
    new.body = origin.body
    origin.parent.children[origin.parent.children.index(origin)] = new

    # steal arguments of origin node
    for child in origin.children:
        if child.body == 'arguments':
            new.children.append(child)
            child.statement_dep_parents[0].extremity = new
    if len(new.children) == 1:
        new.attributes["arguments"] = []
    new.body_list = origin.body_list

    for control_child in origin.parent.control_dep_children:
        if control_child.extremity == origin:
            control_child.extremity = new
            new.control_dep_parents.append(_node.Dependence("control dependence", origin.parent, control_child.label,
                                                            control_child.nearest_statement))
            break
        else:
            print("what happens?")

    for statement_child in origin.parent.statement_dep_children:
        if statement_child.extremity == origin:
            statement_child.extremity = new
            new.statement_dep_parents.append(
                _node.Dependence("statement dependence", origin.parent, statement_child.label,
                                 statement_child.nearest_statement))
            break
        else:
            print("what happens?")


def node_update(node, import_obj):
    if node.name == "CallExpression":
        if node.children[0].name == "Identifier":
            func_name = node.children[0].attributes["name"]
            success = False
            for key, value in import_obj[0].items():
                if func_name == key:
                    success = True
                    data_origin = value.parent.children[0]
                    if is_unwrapped:
                        copy_elem = copy_subtree(value, node, [])
                        copy_elem.body = node.children[0].body
                        node.children[0].parent.children[
                            node.children[0].parent.children.index(node.children[0])] = copy_elem
                    elif data_origin.name == "key":
                        data_origin.set_data_dependency(node.children[0])
                if success:
                    return
    for child in node.children:
        node_update(child, import_obj)


def sweep_the_floor(wasmInstance):
    extremity = wasmInstance.extremity
    nearest_statement = get_nearest_statement(extremity)
    if nearest_statement.name == "VariableDeclaration":
        nearest_statement.parent.children.remove(nearest_statement)
        nearest_statement.parent = None




def reconstruct_pdg(node):
    for child in node.children:
        reconstruct_pdg(child)
        if isinstance(child.WASMSource, hooker.wasmObject.WasmInstance):
            parent = child.parent
            if parent.name == "MemberExpression":
                export_obj = parent.children[1]
                export_name = export_obj.attributes['name']
                if export_name not in ['memory', 'table', 'exports']:
                    current_instance = child.WASMSource
                    for func, elem in current_instance.module.elements.items():
                        if func == export_name:
                            copy_elem = copy.deepcopy(elem.children[0])
                            nearest_statement_son = get_nearest_statement_son(child)
                            # todo： the real situation could not be only callexpression, consider finer grain
                            pure_replace_statement(nearest_statement_son, copy_elem)
                            node_update(copy_elem, current_instance.import_obj)
                            # control_flow_update(copy_elem.parent)
                            # df_scoping(copy_elem, scope.Scope("Replace"), [])
                            sweep_the_floor(current_instance)


magic_num_base64 = 'AGFzbQEAAAA'
magic_num_bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01]


def analyse_WASM_module(wasm_modules):
    for module in wasm_modules:
        binary = module.binary.value
        if binary.startswith(magic_num_base64):
            binary = base64.b64decode(binary)
        with open(temp_wasm, "wb+") as f:
            f.write(binary)
        begin = datetime.datetime.now()
        os.system(wasm2wat + " " + temp_wasm + " -o " + temp_wasm[:-2]+"t")
        OUT = subprocess.run([node_path, parser_path],
                             capture_output=True,  close_fds=True)
        OUT_ast = json.loads(OUT.stdout.decode(encoding="utf-8"))
        OUT_ast_new = {}
        for key, value in OUT_ast.items():
            OUT_ast_new[key] = ast_to_ast_nodes(value, _node.Node("ExpressionStatement"))
        module.elements = OUT_ast_new
        print(datetime.datetime.now() - begin)


def analyse_orphan_module(wasm_modules):
    for module in wasm_modules:
        binary = module.binary
        if binary.startswith(magic_num_base64):
            binary = base64.b64decode(binary)
        with open(temp_wasm, "wb+") as f:
            f.write(binary)
        begin = datetime.datetime.now()
        os.system(wasm2wat + " " + temp_wasm + " -o " + temp_wasm[:-2]+"t")
        subprocess.run([node_path, parser_path],
                             capture_output=True,  close_fds=True)
        OUT_ast = json.loads(open(module_json).read())
        OUT_ast_new = {}
        for key, value in OUT_ast.items():
            OUT_ast_new[key] = ast_to_ast_nodes(value, _node.Statement("BlockStatement", None))
            OUT_ast_new[key].body = "body"
            OUT_ast_new[key].body_list = True
        module.elements = OUT_ast_new
        print(datetime.datetime.now() - begin)

def preprocess_modules(pdg, module1, module2):
    analyse_WASM_module(module1)
    analyse_orphan_module(module2)
    for module in module1:
        current_memory = module.elements.get("memory")
        if current_memory is not None:
            pdg.children.insert(0, current_memory)
    for module in module2:
        current_memory = module.elements.get("memory")
        if current_memory is not None:
            pdg.children.insert(0, current_memory)


def save_js(node, path):
    code = save_json(node)
    path = path.split('/')
    path[-2] = 'new'
    with open('/'.join(path), "w") as f:
        f.write(code)


def main_transformation(path):
    pdg = get_data_flow(path, benchmarks=dict())
    begin = datetime.datetime.now()
    simple_taint_analysis(pdg)
    collect_WASM_init(pdg)
    collect_WASM_object(wasm_inits)
    print(datetime.datetime.now() - begin)
    preprocess_modules(pdg, wasm_modules, orphan_modules)
    begin = datetime.datetime.now()
    initial_WASM_instance(wasm_inits)
    print(datetime.datetime.now() - begin)
    begin = datetime.datetime.now()
    simple_taint_analysis_instance(pdg)
    print(datetime.datetime.now() - begin)
    begin = datetime.datetime.now()
    reconstruct_pdg(pdg)
    print(datetime.datetime.now()-begin)
    save_js(pdg, path)




for file in os.listdir(rootdir)[-1:]:
    print(file)
    wasm_inits = []
    wasm_tables = []
    wasm_memories = []
    wasm_globals = []
    wasm_modules = []
    wasm_instances = []
    orphan_modules = []
    main_transformation(os.path.join(rootdir, file))

