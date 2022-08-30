"""Backports required to run tests on older Python versions."""


import contextlib


if hasattr(contextlib, "nullcontext"):
    nullcontext = contextlib.nullcontext
else:
    import abc
    import _collections_abc
    from contextlib import AbstractContextManager

    class AbstractAsyncContextManager(abc.ABC):

        """An abstract base class for asynchronous context managers."""

        # __class_getitem__ = classmethod(GenericAlias)

        async def __aenter__(self):
            """Return `self` upon entering the runtime context."""
            return self

        @abc.abstractmethod
        async def __aexit__(self, exc_type, exc_value, traceback):
            """Raise any exception triggered within the runtime context."""
            return None

        @classmethod
        def __subclasshook__(cls, C):
            if cls is AbstractAsyncContextManager:
                return _collections_abc._check_methods(C, "__aenter__", "__aexit__")
            return NotImplemented

    class nullcontext(AbstractContextManager, AbstractAsyncContextManager):
        """Context manager that does no additional processing.

        Used as a stand-in for a normal context manager, when a particular
        block of code is only sometimes used with a normal context manager:

        cm = optional_cm if condition else nullcontext()
        with cm:
            # Perform operation, using optional_cm if condition is True
        """

        def __init__(self, enter_result=None):
            self.enter_result = enter_result

        def __enter__(self):
            return self.enter_result

        def __exit__(self, *excinfo):
            pass

        async def __aenter__(self):
            return self.enter_result

        async def __aexit__(self, *excinfo):
            pass
