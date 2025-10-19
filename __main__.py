"""
Entry point for `python -m gitlab_docker_upgrader`.
"""

from .cli import main

if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        print("❌ Unhandled error:")
        traceback.print_exc()
        raise
