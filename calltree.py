import re
from collections import OrderedDict
from typing import cast
from PySide6.QtCore import QSortFilterProxyModel
from PySide6.QtGui import (
    QStandardItemModel,
    QStandardItem,
    QBrush,
    QColor,
)
from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QTreeView
from PySide6.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLineEdit,
    QSpinBox,
    QTextEdit,
    QWidget,
)
from binaryninja.settings import Settings

from binaryninja import BinaryView, Function, MediumLevelILOperation, SymbolType, ThemeColor, log_info, log_warn
from binaryninja.types import CoreSymbol
from binaryninja.enums import SymbolType
from binaryninjaui import getThemeColor

from .demangle import demangle_name


class CalltreeWidget(QWidget):
    def __init__(self):
        super().__init__()
        calltree_layout = QVBoxLayout()
        # Add widgets to the layout
        in_func_depth = Settings().get_integer("calltree.in_depth")
        out_func_depth = Settings().get_integer("calltree.out_depth")
        blacklisted = Settings().get_string_list("calltree.blacklisted")
        hard_blacklist = Settings().get_string_list("calltree.hard_blacklist")
        limit = Settings().get_integer("calltree.limit")
        sinks = Settings().get_string_list("calltree.sinks")

        self.in_calltree = CallTreeLayout("Incoming Calls", in_func_depth, True, \
                                          blacklisted, hard_blacklist, limit, sinks)
        self.out_calltree = CallTreeLayout("Outgoing Calls", out_func_depth, False, \
                                           blacklisted, hard_blacklist, limit, sinks)
        self.cur_func_layout = CurrentFunctionNameLayout()

        self.cur_func_text = self.cur_func_layout.cur_func_text

        calltree_layout.addLayout(self.cur_func_layout)
        calltree_layout.addLayout(self.in_calltree)
        calltree_layout.addLayout(self.out_calltree)

        calltree_layout.setSpacing(0)
        calltree_layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(calltree_layout)


class BNFuncItem(QStandardItem):
    def __init__(self, bv: BinaryView, func: Function | CoreSymbol, sinks: list = None):
        super().__init__()

        symbol = func.symbol if hasattr(func, "symbol") else func
        if symbol.type == SymbolType.FunctionSymbol:
            self.setForeground(QBrush(getThemeColor(ThemeColor.CodeSymbolColor)))
        else:
            self.setForeground(QBrush(getThemeColor(ThemeColor.ImportColor)))

        self.func = func
        self.bv = bv

        name = demangle_name(self.bv, func.name)
        # Append the number of incoming cross-references so that widely-reached
        # helpers (high blast radius) stand out during triage.
        addr = getattr(func, "start", None)
        if addr is None:
            addr = getattr(func, "address", None)
        # it's too slow to count xrefs for every node in the tree, so we don't do it anymore
        #if addr is not None:
        #    xref_count = len(list(bv.get_code_refs(addr)))
        #    name = f"{name}  ({xref_count})"
        # Highlight dangerous sinks (memcpy, system, sprintf, ...) so
        # memory-safety and injection candidates are obvious in the tree.
        if sinks and self._is_sink(func.name, sinks):
            self.setForeground(QBrush(QColor(0xE0, 0x40, 0x40)))
            font = self.font()
            font.setBold(True)
            self.setFont(font)
        self.setText(name)
        self.setEditable(False)

    @staticmethod
    def _is_sink(fname: str, sinks: list) -> bool:
        for p in sinks:
            if re.search(p, fname):
                return True
        return False


class CurrentFunctionNameLayout(QHBoxLayout):
    def __init__(self):
        super().__init__()
        self._binary_view = None
        self._cur_func = None
        self.cur_func_text = QTextEdit()
        self.cur_func_text.setReadOnly(True)
        self.cur_func_text.setMaximumHeight(30)
        self.cur_func_text.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.cur_func_text.setLineWrapMode(QTextEdit.NoWrap)
        self.cur_func_text.mousePressEvent = self.goto_func

        super().addWidget(self.cur_func_text)

    @property
    def binary_view(self):
        return self._binary_view

    @binary_view.setter
    def binary_view(self, bv):
        self._binary_view = bv

    @property
    def cur_func(self):
        return self._cur_func

    @cur_func.setter
    def cur_func(self, func):
        self._cur_func = func

    def goto_func(self, event):
        if self._binary_view is None:
            return
        # Prefer the cached function object. Looking up by the displayed text is
        # unreliable because the label shows the demangled name, while
        # get_functions_by_name expects the raw symbol name.
        cur_func = self._cur_func
        if cur_func is None:
            funcs = self._binary_view.get_functions_by_name(
                self.cur_func_text.toPlainText()
            )
            if not funcs:
                return
            cur_func = funcs[0]
        # make sure that sidebar is updated
        if type(cur_func) == CoreSymbol:
            self._binary_view.navigate(self._binary_view.view, cur_func.address)
        else:
            self._binary_view.navigate(self._binary_view.view, cur_func.start)


# Layout with search bar and expand/collapse buttons
# Takes CallTreeLayout as a parameter
class CallTreeUtilLayout(QHBoxLayout):
    def __init__(self, calltree: object):
        super().__init__()
        self.calltree = calltree
        btn_size = QSize(25, 25)
        self.expand_all_button = QPushButton("+")
        self.expand_all_button.setFixedSize(btn_size)
        self.expand_all_button.clicked.connect(self.calltree.expand_all)

        self.collapse_all_button = QPushButton("-")
        self.collapse_all_button.setFixedSize(btn_size)
        self.collapse_all_button.clicked.connect(self.calltree.collapse_all)

        self.func_filter = QLineEdit()
        self.func_filter.textChanged.connect(self.calltree.onTextChanged)

        self.spinbox = QSpinBox()
        self.spinbox.valueChanged.connect(self.spinbox_changed)
        self.spinbox.setValue(self.calltree.func_depth)
        super().addWidget(self.func_filter)
        super().addWidget(self.expand_all_button)
        super().addWidget(self.collapse_all_button)
        super().addWidget(self.spinbox)

    def spinbox_changed(self):
        self.calltree.func_depth = self.spinbox.value()
        if self.calltree.cur_func is not None:
            self.calltree.update_widget(self.calltree.cur_func)


class CallTreeLayout(QVBoxLayout):
    _CALLEE_CACHE_MAX_ITEMS = 512

    def __init__(self, label_name: str, depth: int, is_caller: bool, blacklist: list, hard_blacklist: list, limit: int, sinks: list = None):
        super().__init__()
        self._cur_func = None
        self._is_caller = is_caller
        self._skip_update = False
        self._limit = limit
        self._blacklisted = blacklist
        self._hard_blacklist = hard_blacklist
        self._sinks = sinks or []
        self._callee_cache = OrderedDict()

        # Creates treeview for all the function calls
        self._treeview = QTreeView()
        self._model = QStandardItemModel()
        self._proxy_model = QSortFilterProxyModel(self.treeview)
        self.proxy_model.setSourceModel(self.model)

        self.treeview.setModel(self.proxy_model)
        self.treeview.setExpandsOnDoubleClick(False)

        # Clicking function on treeview will take you to the function
        self.treeview.clicked.connect(self.goto_first_func_use)
        self.treeview.doubleClicked.connect(self.goto_func)

        self._func_depth = depth
        self._binary_view = None
        self._label_name = label_name
        self.set_label(self.label_name)
        super().addWidget(self.treeview)
        self.util = CallTreeUtilLayout(self)
        super().addLayout(self.util)

    def onTextChanged(self, text):
        self.proxy_model.setRecursiveFilteringEnabled(True)
        self.proxy_model.setFilterRegularExpression(text)
        self.expand_all()

    @property
    def proxy_model(self):
        return self._proxy_model

    @property
    def label_name(self):
        return self._label_name

    @property
    def cur_func(self):
        return self._cur_func

    @cur_func.setter
    def cur_func(self, cur_func):
        self._cur_func = cur_func

    @property
    def is_caller(self):
        return self._is_caller

    @property
    def treeview(self):
        return self._treeview

    @property
    def model(self):
        return self._model

    @property
    def binary_view(self):
        return self._binary_view

    @binary_view.setter
    def binary_view(self, bv : BinaryView):
        self._binary_view = bv
        self._callee_cache.clear()

    @property
    def func_depth(self):
        return self._func_depth

    @func_depth.setter
    def func_depth(self, depth):
        self._func_depth = depth

    @property
    def skip_update(self) -> bool:
        """
        Tells parent view that it should skip updating the sidebar.
        Parent will then set it True once it has been skipped
        """
        return self._skip_update

    @skip_update.setter
    def skip_update(self, value: bool):
        self._skip_update = value

    def get_treeview(self):
        return self.treeview

    def expand_all(self):
        self.treeview.expandAll()

    def collapse_all(self):
        self.treeview.collapseAll()

    def goto_first_func_use(self, index):
        if self._binary_view is None:
            return
        index = self.proxy_model.mapToSource(index)
        item = cast(BNFuncItem, self.model.itemFromIndex(index))
        if item is None:
            return
        bv = item.bv

        parent_item = cast(BNFuncItem, self.model.itemFromIndex(index.parent()))
        parent_func = parent_item.func if parent_item else self.cur_func
        if parent_func is None:
            return

        if self.is_caller:
            caller, callee = item.func, parent_func
        else:
            caller, callee = parent_func, item.func

        # CoreSymbol nodes (imports/thunks) have no call sites to resolve.
        if caller is None or type(caller) == CoreSymbol:
            return

        for ref in caller.call_sites:
            if type(callee) == CoreSymbol:
                if callee.address in bv.get_callees(ref.address, ref.function):
                    break
            else:
                if callee.start in bv.get_callees(ref.address, ref.function):
                    break
        else:
            # callee not found in callers
            return

        self._skip_update = True
        self._binary_view.navigate(self._binary_view.view, ref.address)

    def goto_func(self, index):
        if self._binary_view is None:
            return
        item = cast(BNFuncItem, self.model.itemFromIndex(self.proxy_model.mapToSource(index)))
        if item is None:
            return
        cur_func = item.func
        # make sure that sidebar is updated
        self._skip_update = False
        if type(cur_func) == CoreSymbol:
            self._binary_view.navigate(self._binary_view.view, cur_func.address)
        else:
            self._binary_view.navigate(self._binary_view.view, cur_func.start)

    def filter_blacklisted(self, flist):
        return list(filter(lambda x: x.name not in self._blacklisted, flist))

    def is_blacklisted(self, fname):
        for p in self._blacklisted:
            if re.search(p, fname):
                return True
        return False

    def is_hard_blacklisted(self, fname):
        for p in self._hard_blacklist:
            if re.search(p, fname):
                return True
        return False

    @staticmethod
    def _call_sort_key(call):
        # Functions expose .start; CoreSymbols expose .address. Sort by address
        # then name so the tree order is stable across refreshes.
        addr = getattr(call, "start", None)
        if addr is None:
            addr = getattr(call, "address", 0)
        return (addr, call.name)

    def _truncation_item(self):
        # A non-navigable marker shown when the item/subtree limit is reached so
        # the user knows results were cut off.
        item = QStandardItem(f"{self._limit} limit reached")
        item.setEditable(False)
        item.setSelectable(False)
        return item

    @staticmethod
    def _func_cache_key(func):
        addr = getattr(func, "start", None)
        if addr is None:
            addr = getattr(func, "address", None)
        if addr is None:
            # Fallback for unexpected symbols/functions without a stable address.
            return id(func)
        return addr

    def get_calls(self, func, is_caller: bool):
        """Return sorted calls, limited to the configured cap, with truncation state."""
        # Import/thunk symbols are leaf nodes for call expansion.
        if type(func) == CoreSymbol:
            return [], False

        if is_caller:
            calls = sorted(set(func.callers), key=self._call_sort_key)
            # TODO: test it it's not too slow
            code_refs = self._binary_view.get_code_refs(func.start)
            for code_ref in code_refs:
                f = self._binary_view.get_functions_containing(code_ref.address)
                if f:
                    calls.extend(f)

            if self._limit < 0:
                return calls, False
            was_truncated = len(calls) > self._limit
            return calls[: self._limit], was_truncated

        calls, was_truncated = self.get_callees(func)
        return calls, was_truncated

    def get_callees(self, func):
        if type(func) == CoreSymbol:
            return [], False

        cache_key = (self._func_cache_key(func), self._limit)
        cached = self._callee_cache.get(cache_key)
        if cached is not None:
            self._callee_cache.move_to_end(cache_key)
            return cached

        callees = set()
        for site in func.call_sites:
            if site.mlil and (site.mlil.operation == MediumLevelILOperation.MLIL_CALL or site.mlil.operation == MediumLevelILOperation.MLIL_TAILCALL):
                # print(f"site = 0x{site.address:0x}")
                if site.mlil.dest.operation == MediumLevelILOperation.MLIL_IMPORT:
                    s = self._binary_view.get_symbol_at(site.mlil.dest.value.value)
                    if s:
                        callees.add(s)
                elif site.mlil.dest.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                    f = self._binary_view.get_function_at(site.mlil.dest.value.value)
                    if f:
                        callees.add(f)
                    else:
                        # can be a symbol to __builtin_*
                        s = self._binary_view.get_symbol_at(site.mlil.dest.value.value)
                        if s:
                            callees.add(s)
                elif site.mlil.dest.operation in [MediumLevelILOperation.MLIL_VAR, MediumLevelILOperation.MLIL_LOAD, MediumLevelILOperation.MLIL_LOAD_STRUCT]:
                    # addresses from devi
                    code_refs = self._binary_view.get_code_refs_from(site.address)
                    for code_ref in code_refs:
                        # print(hex(code_ref))
                        f =  self._binary_view.get_function_at(code_ref)
                        if f:
                            callees.add(f)
                    else:
                        if site.mlil.dest.operation == MediumLevelILOperation.MLIL_LOAD_STRUCT: # call from field?
                            log_warn(f"calltree: MLIL_LOAD_STRUCT call at 0x{site.address:0x} may be a call from a field")
                else:
                    log_warn(f"calltree: unknown op at 0x{site.address:0x}")

        sorted_callees = sorted(callees, key=self._call_sort_key)
        if self._limit < 0:
            result = (sorted_callees, False)
        else:
            was_truncated = len(sorted_callees) > self._limit
            result = (sorted_callees[: self._limit], was_truncated)

        self._callee_cache[cache_key] = result
        if len(self._callee_cache) > self._CALLEE_CACHE_MAX_ITEMS:
            self._callee_cache.popitem(last=False)
        return result

    def set_func_calls(self, cur_func, cur_std_item, is_caller: bool, depth=0):
        if type(cur_func) != CoreSymbol:
            func_symbol = cur_func.symbol
        else:
            func_symbol = cur_func
        if func_symbol is None:
            # print(f"no symbol for function {cur_func}")
            return
        if func_symbol.type == SymbolType.SymbolicFunctionSymbol:
            return
        if func_symbol.type == SymbolType.ImportAddressSymbol:
            return
        if func_symbol.type == SymbolType.LibraryFunctionSymbol:
            return
        cur_func_calls, was_truncated = self.get_calls(cur_func, is_caller)

        if not self.is_hard_blacklisted(cur_func.name):
            if depth < self._func_depth:
                if cur_func_calls:
                    for cur_func_call in cur_func_calls:
                        if self.is_blacklisted(cur_func_call.name):
                            continue
                        new_std_item = BNFuncItem(self._binary_view, cur_func_call, self._sinks)
                        cur_std_item.appendRow(new_std_item)
                        # Dont search on function that calls itself
                        if cur_func != cur_func_call:
                            self.set_func_calls(
                                cur_func_call, new_std_item, is_caller, depth + 1
                            )
                if was_truncated:
                    log_info("calltree: subtree limit reached for {}".format(cur_func.name))
                    cur_std_item.appendRow(self._truncation_item())

    def update_widget(self, cur_func: Function):
        if not self.treeview.isVisible():
            return

        # Clear previous calls
        self.clear()
        call_root_node = self.model.invisibleRootItem()

        self.cur_func = cur_func

        cur_func_calls, was_truncated = self.get_calls(cur_func, self.is_caller)

        root_std_items = []

        if not self.is_hard_blacklisted(cur_func.name):
            # Set root std Items
            if cur_func_calls:
                for cur_func_call in cur_func_calls:
                    root_std_items.append(BNFuncItem(self._binary_view, cur_func_call, self._sinks))
                    cur_std_item = root_std_items[-1]
                    if self.is_blacklisted(cur_func_call.name):
                        continue
                    if cur_func != cur_func_call:
                        self.set_func_calls(cur_func_call, cur_std_item, self.is_caller)
            if was_truncated:
                log_info("calltree: items limit reached for {}".format(cur_func.name))
                root_std_items.append(self._truncation_item())

        call_root_node.appendRows(root_std_items)
        self.expand_all()

    def clear(self):
        self.model.clear()
        self.set_label(self.label_name)
        self.expand_all()

    def set_label(self, label_name):
        self.model.setHorizontalHeaderLabels([label_name])
