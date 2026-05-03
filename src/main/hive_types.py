"""
Module for defining hive types and constants.
"""


class HiveType:
    """Defines the available hive types for extraction."""
    WINDOWS = 'windows'
    NTUSERDAT = 'ntuserdat'
    SAM = 'sam'
    SOFTWARE = 'software'
    SYSTEM = 'system'
    SECURITY = 'security'
    ALL = 'all'

    @classmethod
    def all_types(cls):
        """Returns a list with all available hive types."""
        return [
            cls.WINDOWS,
            cls.NTUSERDAT,
            cls.SAM,
            cls.SOFTWARE,
            cls.SYSTEM,
            cls.SECURITY,
            cls.ALL
        ]


class HivePath:
    """Defines the standard paths for Windows hives."""
    HIVES = {
        'SYSTEM': r'/Windows/System32/config/SYSTEM',
        'SOFTWARE': r'/Windows/System32/config/SOFTWARE',
        'SAM': r'/Windows/System32/config/SAM',
        'SECURITY': r'/Windows/System32/config/SECURITY'
    }

    NTUSER_DAT = "NTUSER.DAT"
    USERS_PATH = "/Users/"
    WINDOWS_PATH = "/Windows/"
    NOT_IN_FOLDERS = [".", ".."]
