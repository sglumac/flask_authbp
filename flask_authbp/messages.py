from enum import Enum


def constant(f):
    def fset(self, value):
        raise TypeError
    def fget(self):
        return f(self)
    return property(fget, fset)


class _RegistrationStatus:
    @constant
    def InvalidUsername(self):
        return 'Invalid username'

    @constant
    def InvalidPassword(self):
        return 'Invalid password'

    @constant
    def UserExists(self):
        return 'Username already exists'

    @constant
    def Succcess(self):
        return 'Success'


class _LoginStatus:
    @constant
    def WrongUsernameOrPassword(self):
        return 'Invalid username or password'

    @constant
    def Success(self):
        return 'Success'


RegistrationStatus = _RegistrationStatus()
LoginStatus = _LoginStatus()
