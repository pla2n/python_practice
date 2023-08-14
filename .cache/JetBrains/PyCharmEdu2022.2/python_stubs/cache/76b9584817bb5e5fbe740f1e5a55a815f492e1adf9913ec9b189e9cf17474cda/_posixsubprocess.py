# encoding: utf-8
# module _posixsubprocess
# from (built-in)
# by generator 1.147
""" A POSIX helper for the subprocess module. """
# no imports

# functions

def fork_exec(args, executable_list, close_fds, pass_fds, cwd, env, p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite, errpipe_read, errpipe_write, restore_signals, call_setsid, pgid_to_set, gid, groups_list, uid, preexec_fn): # real signature unknown; restored from __doc__
    """
    fork_exec(args, executable_list, close_fds, pass_fds, cwd, env,
              p2cread, p2cwrite, c2pread, c2pwrite,
              errread, errwrite, errpipe_read, errpipe_write,
              restore_signals, call_setsid, pgid_to_set,
              gid, groups_list, uid,
              preexec_fn)
    
    Forks a child process, closes parent file descriptors as appropriate in the
    child and dups the few that are needed before calling exec() in the child
    process.
    
    If close_fds is true, close file descriptors 3 and higher, except those listed
    in the sorted tuple pass_fds.
    
    The preexec_fn, if supplied, will be called immediately before closing file
    descriptors and exec.
    WARNING: preexec_fn is NOT SAFE if your application uses threads.
             It may trigger infrequent, difficult to debug deadlocks.
    
    If an error occurs in the child process before the exec, it is
    serialized and written to the errpipe_write fd per subprocess.py.
    
    Returns: the child process's PID.
    
    Raises: Only on an error in the parent process.
    """
    pass

# classes

class __loader__(object):
    """
    Meta path import for built-in modules.
    
        All methods are either class or static methods to avoid the need to
        instantiate the class.
    """
    def create_module(spec): # reliably restored by inspect
        """ Create a built-in module """
        pass

    def exec_module(module): # reliably restored by inspect
        """ Exec a built-in module """
        pass

    @classmethod
    def find_module(cls, *args, **kwargs): # real signature unknown
        """
        Find the built-in module.
        
                If 'path' is ever specified then the search is considered a failure.
        
                This method is deprecated.  Use find_spec() instead.
        """
        pass

    @classmethod
    def find_spec(cls, *args, **kwargs): # real signature unknown
        pass

    @classmethod
    def get_code(cls, *args, **kwargs): # real signature unknown
        """ Return None as built-in modules do not have code objects. """
        pass

    @classmethod
    def get_source(cls, *args, **kwargs): # real signature unknown
        """ Return None as built-in modules do not have source code. """
        pass

    @classmethod
    def is_package(cls, *args, **kwargs): # real signature unknown
        """ Return False as built-in modules are never packages. """
        pass

    @classmethod
    def load_module(cls, *args, **kwargs): # real signature unknown
        """
        Load the specified module into sys.modules and return it.
        
            This method is deprecated.  Use loader.exec_module() instead.
        """
        pass

    def module_repr(module): # reliably restored by inspect
        """
        Return repr for the module.
        
                The method is deprecated.  The import machinery does the job itself.
        """
        pass

    def __init__(self, *args, **kwargs): # real signature unknown
        pass

    __weakref__ = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default
    """list of weak references to the object (if defined)"""


    _ORIGIN = 'built-in'
    __dict__ = None # (!) real value is "mappingproxy({'__module__': '_frozen_importlib', '__doc__': 'Meta path import for built-in modules.\\n\\n    All methods are either class or static methods to avoid the need to\\n    instantiate the class.\\n\\n    ', '_ORIGIN': 'built-in', 'module_repr': <staticmethod(<function BuiltinImporter.module_repr at 0x7f286631a8e0>)>, 'find_spec': <classmethod(<function BuiltinImporter.find_spec at 0x7f286631a980>)>, 'find_module': <classmethod(<function BuiltinImporter.find_module at 0x7f286631aa20>)>, 'create_module': <staticmethod(<function BuiltinImporter.create_module at 0x7f286631aac0>)>, 'exec_module': <staticmethod(<function BuiltinImporter.exec_module at 0x7f286631ab60>)>, 'get_code': <classmethod(<function BuiltinImporter.get_code at 0x7f286631aca0>)>, 'get_source': <classmethod(<function BuiltinImporter.get_source at 0x7f286631ade0>)>, 'is_package': <classmethod(<function BuiltinImporter.is_package at 0x7f286631af20>)>, 'load_module': <classmethod(<function _load_module_shim at 0x7f2866319c60>)>, '__dict__': <attribute '__dict__' of 'BuiltinImporter' objects>, '__weakref__': <attribute '__weakref__' of 'BuiltinImporter' objects>})"


# variables with complex values

__spec__ = None # (!) real value is "ModuleSpec(name='_posixsubprocess', loader=<class '_frozen_importlib.BuiltinImporter'>, origin='built-in')"

