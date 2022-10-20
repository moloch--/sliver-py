import functools
import inspect
import logging
import os


def inspect_debug(obj):
    # If we are in dev environment and the result is a class, inspect the class
    if os.getenv("HATCH_ENV_ACTIVE"):
        from rich import inspect as rinspect

        rinspect(obj)


def log_return(level: str):
    """Logs return value of function or coroutine at level specified"""

    def is_async(func):
        """Determine if function or generator is async"""
        return (
            inspect.iscoroutinefunction(func)
            or inspect.isasyncgenfunction(func)
            or inspect.isasyncgen(func)
            or inspect.iscoroutine(func)
        )

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            result = None
            if is_async(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            logging.log(
                logging.getLevelName(level.upper()),
                f"{func.__qualname__} returned:\n{result}",
            )

            # If we are in dev environment and the result is a class, inspect the class
            inspect_debug(result)

            return result

        return wrapper

    return decorator
