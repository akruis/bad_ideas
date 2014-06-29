#
# -*- coding: utf-8 -*-
#
# Copyright (c) 2014 by Anselm Kruis
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#


from __future__ import absolute_import, print_function, division

import sys
import ctypes
import re
import platform
import struct
import thread
import contextlib

__all__ = ['atomic']


def get_address_of_function(api_function_name):
    """
    Get the address of function *api_function_name*.

    :returns: the address
    :rtype: int
    """

    # get the address from the library.
    func_address = ctypes.c_void_p.in_dll(ctypes.pythonapi, api_function_name)
    return ctypes.addressof(func_address)


def get_python_memory(address, length):
    """
    Get the first *length* bytes from function *api_function_name*.

    :returns: a string of length length
    :rtype: str
    """
    assert length > 0
    buf = ctypes.create_string_buffer(length)
    ctypes.memmove(buf, address, length)
    return buf.raw


class GILFinder(object):
    KIND = "{}_{}_{}".format(platform.machine(), "64" if sys.maxsize > 2 ** 32 else "32", sys.platform).replace('-', '_')

    RE_x86_64_64_linux2 = re.compile(br'(?s)\x48\x8b\x3d(?P<offset32>....)')
    RE_AMD64_32_win32 = re.compile(br'(?s)\xa1(?P<addr32>....)\x50')

    def _use_PyEval_ReleaseLock_code(self):
        addr = get_address_of_function("PyEval_ReleaseLock")
        mem = get_python_memory(addr, 20)
        try:
            pattern = getattr(self, "RE_" + self.KIND)
        except AttributeError:
            return None
        match = pattern.match(mem)
        gil = None
        if match and 'offset32' in match.groupdict():
            offset = struct.unpack("@i", match.group('offset32'))[0]
            gil = addr + match.end('offset32') + offset
        elif match and 'addr32' in match.groupdict():
            gil = struct.unpack("@i", match.group('addr32'))[0]
        return gil

    def find_gil(self):
        if platform.python_implementation() != 'CPython':
            return None
        gil = self._use_PyEval_ReleaseLock_code()
        if gil:
            return gil


class PyThread_type_lock(ctypes.Structure):
    pass

LP_PyThread_type_lock = ctypes.POINTER(PyThread_type_lock)
LP_LP_PyThread_type_lock = ctypes.POINTER(LP_PyThread_type_lock)


def get_pointer_to_lock(lock):
    if not type(lock) is thread.LockType:
        raise TypeError("thread.LockType required")
    addr_of_lock = id(lock)
    offset = sys.getsizeof(object())
    p = LP_LP_PyThread_type_lock.from_address(addr_of_lock + offset)
    return p.contents


def get_pointer_to_GIL():
    addr = GILFinder().find_gil()
    if addr is None:
        return None
    p_GIL = LP_LP_PyThread_type_lock.from_address(addr)
    return p_GIL

P_GIL = get_pointer_to_GIL()
if P_GIL:
    GIL = P_GIL.contents

    def atomic(new_checkinterval=sys.getcheckinterval(),
               maxint=sys.maxint,
               getcheckinterval=sys.getcheckinterval,
               setcheckinterval=sys.setcheckinterval):
        setcheckinterval(maxint)
        try:
            reset_check_interval = True
            if ctypes.addressof(P_GIL.contents) == ctypes.addressof(GIL):
                lock = thread.allocate_lock()
                lock.acquire()
                gil = P_GIL.contents
                P_GIL.contents = get_pointer_to_lock(lock)
                try:
                    setcheckinterval(new_checkinterval)
                    reset_check_interval = False
                    yield True
                finally:
                    P_GIL.contents = gil
            else:
                setcheckinterval(new_checkinterval)
                reset_check_interval = False
                yield True
        finally:
            if reset_check_interval:
                setcheckinterval(new_checkinterval)

else:
    def atomic(new_checkinterval=sys.getcheckinterval()):
        sys.setcheckinterval(new_checkinterval)
        yield False
atomic = contextlib.contextmanager(atomic)

if __name__ == '__main__':
    print("Gil pointer address: ", hex(GILFinder().find_gil()))
    pp_gil = get_pointer_to_GIL()
    lock = thread.allocate_lock()
    lock.acquire()
    p_lock = get_pointer_to_lock(lock)
    print("Gil pointer address2: ", hex(ctypes.addressof(pp_gil)))
    print("Gil address: ", hex(ctypes.addressof(pp_gil.contents)))
    p_gil = pp_gil.contents
    print("Gil address: ", hex(ctypes.addressof(p_gil)))
    print("Lock address: ", hex(ctypes.addressof(p_lock)))
    pp_gil.contents = p_lock
    print("Gil address: ", hex(ctypes.addressof(pp_gil.contents)))
    pp_gil.contents = p_gil
    print("Gil address: ", hex(ctypes.addressof(pp_gil.contents)))
    print("fertig")
