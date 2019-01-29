class CliException(Exception):
    pass


class CliError(CliException):
    pass


class CliWarning(CliException):
    pass


class HostNotFoundWarning(CliWarning):
    pass

class SubnetNotFoundWarning(CliWarning):
    pass